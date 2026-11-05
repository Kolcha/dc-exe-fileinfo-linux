#include "DependencyResolver.h"
#include <elf.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <chrono>
extern char** environ;
namespace fileinfo {
fs::path canonicalKey(const fs::path& p) {
    std::error_code ec; auto key=fs::canonical(p,ec);
    if(!ec) return key;
    key=fs::absolute(p,ec); return ec ? p.lexically_normal() : key.lexically_normal();
}
std::shared_ptr<const AnalysisResult> AnalysisContext::inspect(const fs::path& path) {
    auto key=canonicalKey(path);
    if(auto it=cache_.find(key); it!=cache_.end()) return it->second;
    auto result=std::make_shared<AnalysisResult>(inspectBinary(path));
    cache_.emplace(key,result); return result;
}
namespace {
// Fixed executable and arguments: no shell and no inspected path is ever executed.
std::optional<std::string> readLinkerCache() {
    const char* program=nullptr;
    for(const auto* p : {"/sbin/ldconfig", "/usr/sbin/ldconfig", "/bin/ldconfig", "/usr/bin/ldconfig"}) if(access(p,X_OK)==0) { program=p; break; }
    if(!program) return {};
    int pipes[2]; if(pipe2(pipes,O_CLOEXEC)) return {};
    posix_spawn_file_actions_t actions;
    if(posix_spawn_file_actions_init(&actions)) { close(pipes[0]); close(pipes[1]); return {}; }
    int err=posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO);
    err |= posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
    err |= posix_spawn_file_actions_addclose(&actions,pipes[0]);
    err |= posix_spawn_file_actions_addclose(&actions,pipes[1]);
    pid_t pid{};
    char arg[]="-p";
    char* argv[]={const_cast<char*>(program),arg,nullptr};
    if(!err) err=posix_spawn(&pid,program,&actions,nullptr,argv,environ);
    posix_spawn_file_actions_destroy(&actions); close(pipes[1]);
    if(err) { close(pipes[0]); return {}; }
    std::string result; bool ok=true;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while(true) {
        if(std::chrono::steady_clock::now() >= deadline) { ok=false; break; }
        pollfd fd{pipes[0],POLLIN,0};
        int ready=poll(&fd,1,100);
        if(ready<0 && errno==EINTR) continue;
        if(ready<0) { ok=false; break; }
        if(!ready) continue;
        std::array<char,8192> buffer{};
        auto n=read(pipes[0],buffer.data(),buffer.size());
        if(n<0 && errno==EINTR) continue;
        if(n<0) { ok=false; break; }
        if(n==0) break;
        result.append(buffer.data(),static_cast<std::size_t>(n));
        if(result.size()>16*1024*1024) { ok=false; break; }
    }
    close(pipes[0]);
    int status{}; bool exited=false;
    while(ok && std::chrono::steady_clock::now()<deadline) {
        auto rc=waitpid(pid,&status,WNOHANG);
        if(rc==pid) { exited=true; break; }
        if(rc<0 && errno!=EINTR) { exited=true; ok=false; break; }
        poll(nullptr,0,10);
    }
    if(!exited) { kill(pid,SIGKILL); while(waitpid(pid,&status,0)<0 && errno==EINTR) {} return {}; }
    if(!ok || !WIFEXITED(status) || WEXITSTATUS(status)!=0) return {};
    return result;
}
std::string replaceOrigin(std::string value, const fs::path& origin) {
    for(const auto* token : {"${ORIGIN}","$ORIGIN"}) {
        std::size_t pos=0; const std::string key(token);
        while((pos=value.find(key,pos))!=std::string::npos) {
            const auto end=pos+key.size();
            if(key=="$ORIGIN" && end<value.size()) {
                const auto c=value[end];
                if((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_') { pos=end; continue; }
            }
            value.replace(pos,key.size(),origin.string()); pos+=origin.string().size();
        }
    }
    return value;
}
std::vector<fs::path> paths(const std::string& value,const fs::path& requester) {
    std::vector<fs::path> out;
    std::size_t start=0;
    while(true) {
        const auto end=value.find(':',start);
        auto part=replaceOrigin(value.substr(start,end==std::string::npos ? end : end-start),canonicalKey(requester).parent_path());
        // $LIB and $PLATFORM are deliberately unsupported rather than guessed.
        if(part.find('$')==std::string::npos) out.emplace_back(part.empty() ? "." : part);
        if(end==std::string::npos) break;
        start=end+1;
    }
    return out;
}
bool compatible(const ElfIdentity& a,const ElfIdentity& b) {
    if(a.elfClass!=b.elfClass || a.encoding!=b.encoding || a.machine!=b.machine || b.type!=ET_DYN) return false;
    const auto linuxAbi=[](unsigned n) { return n==ELFOSABI_NONE || n==ELFOSABI_LINUX; };
    if(a.osAbi!=b.osAbi && !(linuxAbi(a.osAbi) && linuxAbi(b.osAbi))) return false;
    if(a.abiVersion!=b.abiVersion) return false;
    std::uint32_t mask=0;
    switch(a.machine) {
    case EM_ARM: mask=EF_ARM_EABIMASK | EF_ARM_ABI_FLOAT_HARD | EF_ARM_ABI_FLOAT_SOFT; break;
    case EM_MIPS: mask=EF_MIPS_ABI2 | EF_MIPS_ARCH | 0x0000f000; break;
    case EM_RISCV: mask=EF_RISCV_FLOAT_ABI | EF_RISCV_RVE; break;
    case EM_PPC64: mask=EF_PPC64_ABI; break;
    case EM_LOONGARCH: mask=0x7; break;
    default: break;
    }
    return (a.flags & mask)==(b.flags & mask);
}
std::vector<fs::path> defaultDirs(const ElfIdentity& id) {
    std::string triple;
    switch(id.machine) {
    case EM_X86_64: triple=id.elfClass==ELFCLASS32 ? "x86_64-linux-gnux32" : "x86_64-linux-gnu"; break;
    case EM_386: triple="i386-linux-gnu"; break;
    case EM_AARCH64: triple=id.encoding==ELFDATA2MSB ? "aarch64_be-linux-gnu" : "aarch64-linux-gnu"; break;
    case EM_ARM: triple=(id.flags & EF_ARM_ABI_FLOAT_HARD) ? "arm-linux-gnueabihf" : "arm-linux-gnueabi"; break;
    case EM_RISCV: if(id.elfClass==ELFCLASS64) triple="riscv64-linux-gnu"; break;
    case EM_PPC64: triple=id.encoding==ELFDATA2LSB ? "powerpc64le-linux-gnu" : "powerpc64-linux-gnu"; break;
    case EM_PPC: triple="powerpc-linux-gnu"; break;
    case EM_S390: triple="s390x-linux-gnu"; break;
    case EM_LOONGARCH: triple="loongarch64-linux-gnu"; break;
    default: break;
    }
    std::vector<fs::path> out;
    if(!triple.empty()) { out.emplace_back("/lib/"+triple); out.emplace_back("/usr/lib/"+triple); }
    if(id.machine==EM_386) { out.emplace_back("/lib32"); out.emplace_back("/usr/lib32"); }
    if(id.machine==EM_X86_64 && id.elfClass==ELFCLASS32) { out.emplace_back("/libx32"); out.emplace_back("/usr/libx32"); }
    if(id.elfClass==ELFCLASS64) { out.emplace_back("/lib64"); out.emplace_back("/usr/lib64"); }
    out.emplace_back("/lib"); out.emplace_back("/usr/lib");
    return out;
}
}
DependencyResolver::DependencyResolver() {
    auto output=readLinkerCache();
    if(!output) { cacheDiagnostic_="System linker cache unavailable; using ELF search paths and standard architecture directories."; return; }
    std::istringstream lines(*output); std::string line;
    while(std::getline(lines,line)) {
        auto arrow=line.find(" => "); if(arrow==std::string::npos) continue;
        std::istringstream left(line.substr(0,arrow)); std::string name; left>>name;
        auto target=line.substr(arrow+4);
        if(!name.empty() && !target.empty() && target.front()=='/') linkerCache_[name].emplace_back(target);
    }
    if(linkerCache_.empty()) cacheDiagnostic_="System linker cache output was not recognized; using other search locations.";
}
SearchContext DependencyResolver::childrenContext(const AnalysisResult& r,const SearchContext& context) const {
    auto out=context;
    if(r.elf && !r.elf->runpath && r.elf->rpath) {
        auto own=paths(*r.elf->rpath,r.path);
        out.inheritedRpaths.insert(out.inheritedRpaths.begin(),own.begin(),own.end());
    }
    return out;
}
ResolutionResult DependencyResolver::resolve(const Dependency& dependency,const AnalysisResult& requester,const SearchContext& context) {
    if(!requester.elf) return {ResolutionStatus::Error,{},"No supported linking metadata for the requesting binary."};
    const auto& link=*requester.elf;
    std::vector<fs::path> candidates;
    auto name=replaceOrigin(dependency.name,canonicalKey(requester.path).parent_path());
    if(name.find('$')!=std::string::npos) return {ResolutionStatus::Error,{},"Unsupported dynamic string token in dependency name."};
    const auto defaults=defaultDirs(link.identity);
    if(name.find('/')!=std::string::npos) candidates.emplace_back(name);
    else {
        auto add=[&](const std::vector<fs::path>& dirs) { for(const auto& dir:dirs) candidates.push_back(dir/name); };
        // RUNPATH suppresses this object's RPATH and ancestor RPATH search for its direct requests.
        if(!link.runpath) {
            if(link.rpath) add(paths(*link.rpath,requester.path));
            add(context.inheritedRpaths);
        }
        if(link.runpath) add(paths(*link.runpath,requester.path));
        if(auto it=linkerCache_.find(name);it!=linkerCache_.end()) for(const auto& candidate:it->second) {
            bool isDefault=false;
            for(const auto& dir:defaults) if(canonicalKey(candidate.parent_path())==canonicalKey(dir)) { isDefault=true; break; }
            if(!link.noDefaultLib || !isDefault) candidates.push_back(candidate);
        }
        if(!link.noDefaultLib) add(defaults);
    }
    bool incompatible=false, invalid=false; std::string details;
    std::vector<fs::path> visited;
    for(const auto& candidate:candidates) {
        auto key=canonicalKey(candidate);
        if(std::find(visited.begin(),visited.end(),key)!=visited.end()) continue;
        visited.push_back(key);
        std::error_code ec;
        if(!fs::exists(candidate,ec)) { if(ec) { invalid=true; details += candidate.string()+": "+ec.message()+"\n"; } continue; }
        auto identity=readElfIdentity(candidate);
        if(!identity) { invalid=true; details+=candidate.string()+": unreadable or invalid shared ELF object\n"; continue; }
        if(!compatible(link.identity,*identity)) { incompatible=true; details+=candidate.string()+": incompatible ELF architecture, ABI, flags or object type\n"; continue; }
        // Keep the selected spelling for display; the metadata cache uses canonical keys.
        return {ResolutionStatus::Found,candidate,{}};
    }
    return {incompatible ? ResolutionStatus::Incompatible : invalid ? ResolutionStatus::Error : ResolutionStatus::NotFound,{},
        "Could not resolve "+dependency.name+" for "+requester.path.string()+". LD_LIBRARY_PATH is ignored.\n"+details};
}
}
