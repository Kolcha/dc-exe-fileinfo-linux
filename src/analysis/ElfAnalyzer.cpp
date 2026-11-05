#include "ElfAnalyzer.h"
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>

namespace fileinfo {
namespace {
struct File {
    int fd;
    explicit File(const fs::path& p) : fd(open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)) {}
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    ~File() { if (fd >= 0) close(fd); }
};
struct ElfCloser { void operator()(Elf* e) const { elf_end(e); } };
std::string hex(std::uint64_t n) { std::ostringstream s; s << "0x" << std::hex << n; return s.str(); }
std::string fileSize(std::uintmax_t size) {
    static constexpr const char* units[] = {"bytes", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(size);
    unsigned unit = 0;
    while(value >= 1024 && unit < 4) { value /= 1024; ++unit; }
    if(!unit) return std::to_string(size) + " bytes";
    std::ostringstream text;
    text << std::fixed << std::setprecision(1) << value << ' ' << units[unit]
         << " (" << size << " bytes)";
    return text.str();
}
std::string machineName(unsigned n) {
    switch(n) {
    case EM_386: return "Intel 80386"; case EM_X86_64: return "x86-64";
    case EM_ARM: return "ARM"; case EM_AARCH64: return "AArch64";
    case EM_RISCV: return "RISC-V"; case EM_PPC: return "PowerPC";
    case EM_PPC64: return "PowerPC64"; case EM_MIPS: return "MIPS";
    case EM_S390: return "IBM S/390"; case EM_LOONGARCH: return "LoongArch";
    default: return "Unknown (" + std::to_string(n) + ")";
    }
}
std::string abiName(unsigned n) {
    switch(n) {
    case ELFOSABI_NONE: return "System V"; case ELFOSABI_LINUX: return "GNU/Linux";
    case ELFOSABI_FREEBSD: return "FreeBSD"; case ELFOSABI_NETBSD: return "NetBSD";
    case ELFOSABI_SOLARIS: return "Solaris";
    default: return "Unknown (" + std::to_string(n) + ")";
    }
}
std::string typeName(unsigned n) {
    switch(n) { case ET_EXEC: return "ET_EXEC"; case ET_DYN: return "ET_DYN";
    case ET_REL: return "ET_REL"; case ET_CORE: return "ET_CORE";
    default: return "Unknown (" + std::to_string(n) + ")"; }
}
bool within(std::uint64_t off, std::uint64_t count, std::uint64_t size) {
    return off <= size && count <= size - off;
}
bool readAt(int fd, std::uint64_t off, void* data, std::size_t size) {
    auto* out = static_cast<char*>(data);
    while (size) {
        auto n = pread(fd, out, size, static_cast<off_t>(off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        out += n; off += n; size -= n;
    }
    return true;
}
}
bool isElf(const fs::path& path) {
    File f(path); std::array<unsigned char, 4> magic{};
    return f.fd >= 0 && readAt(f.fd, 0, magic.data(), magic.size()) &&
        magic == std::array<unsigned char,4>{0x7f, 'E', 'L', 'F'};
}
std::optional<ElfIdentity> readElfIdentity(const fs::path& path) {
    File file(path); struct stat st{};
    if(file.fd < 0 || fstat(file.fd, &st) || !S_ISREG(st.st_mode) || elf_version(EV_CURRENT) == EV_NONE) return {};
    std::unique_ptr<Elf, ElfCloser> elf(elf_begin(file.fd, ELF_C_READ, nullptr));
    GElf_Ehdr eh{};
    if(!elf || elf_kind(elf.get()) != ELF_K_ELF || !gelf_getehdr(elf.get(), &eh)) return {};
    if(eh.e_version != EV_CURRENT || eh.e_ident[EI_VERSION] != EV_CURRENT ||
       (eh.e_ident[EI_DATA] != ELFDATA2LSB && eh.e_ident[EI_DATA] != ELFDATA2MSB) ||
       eh.e_ehsize != gelf_fsize(elf.get(), ELF_T_EHDR, 1, EV_CURRENT)) return {};
    return ElfIdentity{eh.e_ident[EI_CLASS],eh.e_ident[EI_DATA],eh.e_ident[EI_OSABI],eh.e_ident[EI_ABIVERSION],eh.e_machine,eh.e_type,eh.e_flags};
}
std::unique_ptr<BinaryAnalyzer> createAnalyzer(const fs::path& p) {
    if (isElf(p)) return std::make_unique<ElfAnalyzer>();
    return {};
}
AnalysisResult inspectBinary(const fs::path& p) {
    if (auto analyzer = createAnalyzer(p)) return analyzer->inspect(p);
    AnalysisResult r; r.path = p;
    r.diagnostics.push_back({DiagnosticSeverity::Error, "File is unreadable or its format is not recognized."});
    return r;
}
AnalysisResult ElfAnalyzer::inspect(const fs::path& path) const {
    AnalysisResult r; r.path = path; r.format = BinaryFormat::ELF; r.status = AnalysisStatus::Complete;
    auto warn = [&](std::string s) { if(r.diagnostics.size() < 128) r.diagnostics.push_back({DiagnosticSeverity::Warning, std::move(s)}); if(r.status == AnalysisStatus::Complete) r.status = AnalysisStatus::Partial; };
    auto fail = [&](std::string s) { r.diagnostics.push_back({DiagnosticSeverity::Error, std::move(s)}); r.status = AnalysisStatus::Error; };
    File file(path); struct stat st{};
    if(file.fd < 0 || fstat(file.fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) { fail("Cannot read a regular file."); return r; }
    r.size = st.st_size;
    r.groups.push_back({"File", {{"Name", path.filename().string()}, {"Requested path", path.string()}, {"Size", fileSize(r.size)}, {"Format", "ELF"}}});
    if(elf_version(EV_CURRENT) == EV_NONE) { fail("libelf initialization failed."); return r; }
    std::unique_ptr<Elf, ElfCloser> elf(elf_begin(file.fd, ELF_C_READ, nullptr));
    GElf_Ehdr eh{};
    if(!elf || elf_kind(elf.get()) != ELF_K_ELF || !gelf_getehdr(elf.get(), &eh)) { fail("Invalid or truncated ELF header."); return r; }
    auto& e = *elf;
    if(eh.e_ident[EI_VERSION] != EV_CURRENT || eh.e_version != EV_CURRENT ||
       (eh.e_ident[EI_DATA] != ELFDATA2LSB && eh.e_ident[EI_DATA] != ELFDATA2MSB)) { fail("Unsupported ELF encoding or version."); return r; }
    const auto headerSize = gelf_fsize(&e, ELF_T_EHDR, 1, EV_CURRENT);
    if(!headerSize || eh.e_ehsize != headerSize) { fail("Invalid ELF header size."); return r; }
    r.elf = ElfLinking{{eh.e_ident[EI_CLASS], eh.e_ident[EI_DATA], eh.e_ident[EI_OSABI], eh.e_ident[EI_ABIVERSION], eh.e_machine, eh.e_type, eh.e_flags}, {}, {}, false};
    r.groups.push_back({"ELF", {{"Binary kind", "Unknown"}, {"ELF type", typeName(eh.e_type)}, {"Architecture", machineName(eh.e_machine)}, {"Bitness", gelf_getclass(&e) == ELFCLASS64 ? "64-bit" : "32-bit"}, {"Endianness", eh.e_ident[EI_DATA] == ELFDATA2LSB ? "Little endian" : "Big endian"}, {"OS ABI", abiName(eh.e_ident[EI_OSABI])}, {"ABI version", std::to_string(eh.e_ident[EI_ABIVERSION])}, {"Entry point", hex(eh.e_entry)}}});
    if(eh.e_type == ET_CORE) { r.kind="Core dump (unsupported)"; r.groups[1].properties[0].value=r.kind; r.status = AnalysisStatus::Unsupported; warn("ELF core dumps are not supported."); return r; }
    if(eh.e_type != ET_EXEC && eh.e_type != ET_DYN && eh.e_type != ET_REL) { r.status = AnalysisStatus::Unsupported; warn("Unsupported ELF object type."); return r; }
    std::vector<GElf_Phdr> phdrs;
    std::size_t phnum{};
    if(elf_getphdrnum(&e, &phnum) || (phnum && (eh.e_phentsize != gelf_fsize(&e, ELF_T_PHDR, 1, EV_CURRENT) || !within(eh.e_phoff, std::uint64_t(phnum) * eh.e_phentsize, r.size)))) {
        warn("Invalid program-header table."); phnum = 0;
    }
    // Bound metadata work on hostile inputs, independently of the mapped file size.
    if(phnum > 65536) { warn("Program-header safety limit reached."); phnum = 65536; }
    for(std::size_t i=0; i<phnum; ++i) {
        GElf_Phdr ph{};
        if(!gelf_getphdr(&e, static_cast<int>(i), &ph)) { warn("Cannot decode program header."); break; }
        if(!within(ph.p_offset, ph.p_filesz, r.size)) { warn("Program segment extends beyond the file."); continue; }
        if(ph.p_type == PT_LOAD && ph.p_filesz > ph.p_memsz) { warn("Load segment has a file size larger than its memory size."); continue; }
        phdrs.push_back(ph);
    }
    auto virtualOffset = [&](std::uint64_t addr, std::uint64_t len) -> std::optional<std::uint64_t> {
        for(const auto& p : phdrs) if(p.p_type == PT_LOAD && addr >= p.p_vaddr && within(addr-p.p_vaddr, len, p.p_filesz)) return p.p_offset + (addr-p.p_vaddr);
        return {};
    };
    std::string interpreter, soname, buildId, abiTag;
    bool dynamic=false, relro=false, bindNow=false, pie=false;
    std::optional<bool> executableStack;
    std::optional<std::uint64_t> straddr, strsize;
    std::vector<std::pair<std::int64_t,std::uint64_t>> strings;
    for(const auto& ph : phdrs) {
        if(ph.p_type == PT_GNU_RELRO) relro = true;
        if(ph.p_type == PT_GNU_STACK) executableStack = (ph.p_flags & PF_X) != 0;
        if(ph.p_type == PT_INTERP) {
            if(ph.p_filesz == 0 || ph.p_filesz > 65536) { warn("Invalid interpreter size."); continue; }
            std::string text(ph.p_filesz, '\0');
            if(readAt(file.fd, ph.p_offset, text.data(), text.size()) && text.back() == '\0') interpreter = text.c_str();
            else warn("Invalid interpreter string.");
        }
        if(ph.p_type != PT_DYNAMIC) continue;
        if(dynamic) { warn("Multiple dynamic segments; using the first."); continue; }
        dynamic = true;
        const auto entsize = gelf_fsize(&e, ELF_T_DYN, 1, EV_CURRENT);
        if(!entsize || ph.p_filesz % entsize || ph.p_filesz / entsize > 65536) { warn("Invalid or oversized dynamic segment."); continue; }
        auto* data = elf_getdata_rawchunk(&e, ph.p_offset, ph.p_filesz, ELF_T_DYN);
        if(!data) { warn("Cannot decode dynamic segment."); continue; }
        bool terminated=false;
        for(std::size_t i=0; i<ph.p_filesz/entsize; ++i) {
            GElf_Dyn d{};
            if(!gelf_getdyn(data, static_cast<int>(i), &d)) { warn("Invalid dynamic entry."); break; }
            if(d.d_tag == DT_NULL) { terminated=true; break; }
            switch(d.d_tag) {
            case DT_STRTAB: straddr = d.d_un.d_ptr; break;
            case DT_STRSZ: strsize = d.d_un.d_val; break;
            case DT_NEEDED: case DT_SONAME: case DT_RPATH: case DT_RUNPATH: strings.emplace_back(d.d_tag,d.d_un.d_val); break;
            case DT_BIND_NOW: bindNow=true; break;
            case DT_FLAGS: bindNow |= (d.d_un.d_val & DF_BIND_NOW) != 0; break;
            case DT_FLAGS_1:
                bindNow |= (d.d_un.d_val & DF_1_NOW) != 0;
                pie |= (d.d_un.d_val & DF_1_PIE) != 0;
                r.elf->noDefaultLib = (d.d_un.d_val & DF_1_NODEFLIB) != 0; break;
            default: break;
            }
        }
        if(!terminated) warn("Dynamic segment has no DT_NULL terminator.");
    }
    if(!strings.empty()) {
        auto off = straddr && strsize ? virtualOffset(*straddr, *strsize) : std::nullopt;
        if(!off) warn("Dynamic string table is missing or outside file-backed PT_LOAD segments.");
        else {
            std::size_t stringBudget = 16 * 1024 * 1024;
            for(auto [tag,index] : strings) {
                if(index >= *strsize) { warn("Dynamic string offset is outside its string table."); continue; }
                // Read only the requested string, with an explicit memory bound.
                auto count = static_cast<std::size_t>(std::min<std::uint64_t>(*strsize-index, 65536));
                if(count > stringBudget) { warn("Dynamic string safety limit reached."); break; }
                stringBudget -= count;
                std::string text(count, '\0');
                if(!readAt(file.fd, *off+index, text.data(), count)) { warn("Cannot read dynamic string."); continue; }
                auto end = text.find('\0');
                if(end == std::string::npos) { warn("Unterminated or oversized dynamic string."); continue; }
                text.resize(end);
                switch(tag) {
                case DT_NEEDED: if(text.empty()) warn("Empty DT_NEEDED declaration."); else r.dependencies.push_back({text}); break;
                case DT_SONAME: soname=text; break;
                case DT_RPATH: r.elf->rpath=text; break;
                case DT_RUNPATH: r.elf->runpath=text; break;
                default: break;
                }
            }
        }
    }
    std::size_t noteBudget = 16 * 1024 * 1024;
    for(const auto& ph : phdrs) if(ph.p_type == PT_NOTE && ph.p_filesz) {
        if(ph.p_filesz > noteBudget) { warn("ELF note safety limit reached."); continue; }
        noteBudget -= ph.p_filesz;
        auto* data = elf_getdata_rawchunk(&e, ph.p_offset, ph.p_filesz, ELF_T_NHDR);
        if(!data) { warn("Cannot decode ELF notes."); continue; }
        std::size_t offset=0;
        while(offset < data->d_size) {
            GElf_Nhdr note{}; std::size_t nameOff{}, descOff{};
            const auto next = gelf_getnote(data, offset, &note, &nameOff, &descOff);
            if(!next || next <= offset || !within(nameOff,note.n_namesz,data->d_size) || !within(descOff,note.n_descsz,data->d_size)) { warn("Malformed ELF note."); break; }
            const auto* bytes = static_cast<const unsigned char*>(data->d_buf);
            if(note.n_namesz == 4 && std::memcmp(bytes+nameOff,"GNU\0",4) == 0) {
                if(note.n_type == NT_GNU_BUILD_ID && note.n_descsz <= 4096) {
                    std::ostringstream s; s << std::hex << std::setfill('0');
                    for(std::size_t i=0; i<note.n_descsz; ++i) s << std::setw(2) << unsigned(bytes[descOff+i]);
                    buildId=s.str();
                }
                if(note.n_type == NT_GNU_ABI_TAG && note.n_descsz == 16) {
                    auto word = [&](std::size_t i) { std::uint32_t v=0; for(unsigned b=0;b<4;++b) { unsigned shift = eh.e_ident[EI_DATA] == ELFDATA2LSB ? b*8 : (3-b)*8; v |= std::uint32_t(bytes[descOff+i*4+b]) << shift; } return v; };
                    const auto os = word(0);
                    abiTag = (os == 0 ? "Linux" : os == 1 ? "GNU" : os == 2 ? "Solaris" : os == 3 ? "FreeBSD" : "OS " + std::to_string(os)) + std::string(" ") + std::to_string(word(1)) + "." + std::to_string(word(2)) + "." + std::to_string(word(3));
                }
            }
            offset=next;
        }
    }
    bool symtab=false, debug=false, sectionsKnown=false;
    std::size_t shnum{}, shstr{};
    if(!eh.e_shoff && eh.e_shnum == 0) { /* Sectionless files are valid. */ }
    else if(elf_getshdrnum(&e,&shnum) || shnum > 1048576 || eh.e_shentsize != gelf_fsize(&e,ELF_T_SHDR,1,EV_CURRENT) || !within(eh.e_shoff,std::uint64_t(shnum)*eh.e_shentsize,r.size)) warn("Invalid section-header table.");
    else {
        sectionsKnown=true;
        bool namesKnown = elf_getshdrstrndx(&e,&shstr) == 0 && shstr != SHN_UNDEF;
        for(std::size_t i=0;i<shnum;++i) {
            auto* scn=elf_getscn(&e,i); GElf_Shdr sh{};
            if(!scn || !gelf_getshdr(scn,&sh) || (sh.sh_type != SHT_NOBITS && !within(sh.sh_offset,sh.sh_size,r.size))) { sectionsKnown=false; warn("Invalid section header or bounds."); break; }
            symtab |= sh.sh_type == SHT_SYMTAB;
            if(namesKnown) {
                const auto* name=elf_strptr(&e,shstr,sh.sh_name);
                if(!name) { warn("Invalid section name."); namesKnown=false; }
                else { const std::string_view n(name); debug |= n.starts_with(".debug_") || n.starts_with(".zdebug_") || n == ".gnu_debuglink" || n == ".gnu_debugdata"; }
            }
        }
        if(!namesKnown && !debug) sectionsKnown=false;
    }
    if(eh.e_type == ET_REL) r.kind="Relocatable object";
    else if(eh.e_type == ET_EXEC) r.kind="Executable";
    else if(pie || !interpreter.empty()) r.kind="PIE executable";
    else if(!soname.empty()) r.kind="Shared library";
    else r.kind="Shared object (role undetermined)";
    r.groups[1].properties[0].value = r.kind;
    std::string linking;
    if(!interpreter.empty() || !r.dependencies.empty()) linking="Dynamic";
    else if(eh.e_type == ET_REL) linking="Not applicable";
    else if(r.status != AnalysisStatus::Complete) linking="Unknown (incomplete analysis)";
    else if(eh.e_type == ET_EXEC || (eh.e_type == ET_DYN && pie)) linking="Static";
    else if(dynamic) linking="Self-contained dynamic object (no DT_NEEDED)";
    else linking="Unknown";
    PropertyGroup build{"Linking & Build", {{"Linking", linking}}};
    auto add = [&](const std::string& key, const std::string& value) { if(!value.empty()) build.properties.push_back({key,value}); };
    add("Interpreter",interpreter); add("SONAME",soname);
    if(r.elf->rpath) build.properties.push_back({"RPATH",*r.elf->rpath});
    if(r.elf->runpath) build.properties.push_back({"RUNPATH",*r.elf->runpath});
    add("GNU Build ID",buildId); add("GNU ABI tag",abiTag);
    add("Stripped",symtab ? "No (symbol table present)" : sectionsKnown && eh.e_type != ET_REL ? "Yes (no static symbol table)" : "Unknown");
    add("Debug information",debug ? "Present or externally referenced" : sectionsKnown ? "Not found" : "Unknown");
    r.groups.push_back(std::move(build));
    r.groups.push_back({"Security", {{"NX stack",executableStack ? (*executableStack ? "Disabled" : "Enabled") : "Unknown"}, {"RELRO",relro ? (bindNow ? "Full" : "Partial") : "Absent"}, {"PIE",eh.e_type == ET_DYN ? (pie || !interpreter.empty() ? "Yes" : "Unknown (ET_DYN object)") : eh.e_type == ET_EXEC ? "No" : "Not applicable"}}});
    return r;
}
}

#include "Symbols.h"
#include <cxxabi.h>
#include <cstdlib>
#include <map>
namespace fileinfo {
SymbolAnalysisResult analyzeSymbols(const fs::path& path) {
    SymbolAnalysisResult r;
    auto warn=[&](const char* s){ r.status=AnalysisStatus::Partial; if(r.diagnostics.size()<128) r.diagnostics.push_back({DiagnosticSeverity::Warning,s}); };
    File f(path); struct stat st{};
    if(f.fd<0 || fstat(f.fd,&st) || !S_ISREG(st.st_mode) || st.st_size<0 || elf_version(EV_CURRENT)==EV_NONE) {warn("Cannot open ELF file."); r.status=AnalysisStatus::Error; return r;}
    std::unique_ptr<Elf,ElfCloser> e(elf_begin(f.fd,ELF_C_READ,nullptr)); GElf_Ehdr eh{};
    if(!e || !gelf_getehdr(e.get(),&eh)) {warn("Invalid ELF header."); return r;}
    if(eh.e_type!=ET_DYN && eh.e_type!=ET_EXEC && eh.e_type!=ET_REL) {r.status=AnalysisStatus::Unsupported; return r;}
    // All traversal limits are independent of file size: one million symbols,
    // 65536 metadata records, 64 MiB strings, and 256 MiB total decoded names.
    constexpr uint64_t limit=1000000;
    std::vector<GElf_Phdr> loads; std::map<int64_t,uint64_t> tags;
    size_t n=0; elf_getphdrnum(e.get(),&n);
    if(n>65536) {warn("Too many program headers."); return r;}
    for(size_t i=0;i<n;++i) {GElf_Phdr p{}; if(!gelf_getphdr(e.get(),i,&p) || !within(p.p_offset,p.p_filesz,st.st_size)) {warn("Invalid program segment."); continue;} if(p.p_type==PT_LOAD) loads.push_back(p);
        if(p.p_type==PT_DYNAMIC) {auto z=gelf_fsize(e.get(),ELF_T_DYN,1,EV_CURRENT); if(!z || p.p_filesz/z>65536) {warn("Invalid dynamic segment."); continue;} auto*d=elf_getdata_rawchunk(e.get(),p.p_offset,p.p_filesz,ELF_T_DYN); if(!d) continue;
            for(size_t j=0;j<p.p_filesz/z;++j){GElf_Dyn v{}; if(!gelf_getdyn(d,j,&v)) break; if(v.d_tag==DT_NULL) break; tags.emplace(v.d_tag,v.d_un.d_val);}
        }
    }
    auto offset=[&](uint64_t a,uint64_t z)->std::optional<uint64_t>{for(auto&p:loads) if(a>=p.p_vaddr && within(a-p.p_vaddr,z,p.p_filesz)) return p.p_offset+a-p.p_vaddr; return {};};
    auto chunk=[&](uint64_t a,uint64_t z,Elf_Type t)->Elf_Data*{auto o=offset(a,z); return o ? elf_getdata_rawchunk(e.get(),*o,z,t):nullptr;};
    auto word=[&](uint64_t a)->std::optional<uint32_t>{auto*d=chunk(a,4,ELF_T_WORD); if(!d || !d->d_buf) return {}; return *static_cast<uint32_t*>(d->d_buf);};
    uint64_t count=0,symoff=0,stroff=0,strsize=0;
    const auto entsize=gelf_fsize(e.get(),ELF_T_SYM,1,EV_CURRENT);
    size_t sections=0; elf_getshdrnum(e.get(),&sections);
    if(sections>limit) {warn("Section limit exceeded."); sections=0;}
    for(size_t i=0;i<sections;++i){GElf_Shdr s{},str{}; auto*sc=elf_getscn(e.get(),i); if(!sc || !gelf_getshdr(sc,&s) || s.sh_type!=SHT_DYNSYM) continue;
        auto*ss=elf_getscn(e.get(),s.sh_link); if(s.sh_entsize!=entsize || !ss || !gelf_getshdr(ss,&str) || !within(s.sh_offset,s.sh_size,st.st_size) || !within(str.sh_offset,str.sh_size,st.st_size)) {warn("Invalid dynamic symbol section."); continue;}
        count=s.sh_size/entsize; symoff=s.sh_offset; stroff=str.sh_offset; strsize=str.sh_size; break;
    }
    if(!count && tags.count(DT_SYMTAB)) {
        if(tags[DT_SYMENT]!=entsize) {warn("Invalid dynamic symbol entry size."); return r;}
        if(tags.count(DT_HASH)) {auto a=tags[DT_HASH]; auto buckets=word(a), chains=word(a+4); if(buckets && chains && *chains<=limit && offset(a,8+4ull*(*buckets+uint64_t(*chains)))) count=*chains; else warn("Invalid ELF hash table.");}
        if(!count && tags.count(DT_GNU_HASH)) {
            auto a=tags[DT_GNU_HASH]; auto nb=word(a),base=word(a+4), bloom=word(a+8);
            if(nb && base && bloom && *nb<=limit && *base<=limit && *bloom<=limit && *bloom) {
                uint64_t buckets=a+16+uint64_t(*bloom)*(gelf_getclass(e.get())==ELFCLASS64?8:4); uint64_t chains=buckets+4ull*(*nb); count=*base;
                uint64_t work=0;
                for(uint64_t b=0;b<*nb;++b){auto v=word(buckets+4*b); if(!v){warn("Truncated GNU hash buckets."); break;} if(!*v) continue; if(*v<*base || *v>=limit){warn("Invalid GNU hash index."); continue;}
                    uint64_t j=*v; for(;;++j){if(j>=limit || ++work>limit){warn("GNU hash safety limit reached."); break;} auto c=word(chains+4*(j-*base)); if(!c){warn("Truncated GNU hash chain."); break;} count=std::max(count,j+1); if(*c&1) break;}
                    if(work>limit) break;
                }
            } else warn("Invalid GNU hash header.");
        }
        auto so=offset(tags[DT_SYMTAB],count*entsize), to=offset(tags[DT_STRTAB],tags[DT_STRSZ]);
        if(!count || !so || !to){warn("Cannot safely determine dynamic symbol range."); return r;} symoff=*so; stroff=*to; strsize=tags[DT_STRSZ];
    }
    if(!count) return r;
    if(count>limit || strsize>64*1024*1024 || !entsize) {warn("Symbol safety limit exceeded."); return r;}
    std::string strings(strsize,'\0'); if(!readAt(f.fd,stroff,strings.data(),strings.size())) {warn("Cannot read symbol strings."); return r;}
    auto name=[&](uint64_t i)->std::string{if(i>=strings.size()){warn("Invalid symbol string offset."); return {};} auto end=strings.find('\0',i); if(end==std::string::npos){warn("Unterminated symbol string."); return {};} return strings.substr(i,end-i);};
    std::map<unsigned,std::string> versions;
    auto versionsAt=[&](bool definitions){auto tag=definitions?DT_VERDEF:DT_VERNEED; auto num=definitions?DT_VERDEFNUM:DT_VERNEEDNUM; if(!tags.count(tag)) return;
        uint64_t a=tags[tag], total=tags[num]; if(total>65536){warn("Version traversal limit exceeded."); return;}
        for(uint64_t i=0;i<total;++i){uint64_t next=0;
            if(definitions){auto*d=chunk(a,20,ELF_T_VDEF); GElf_Verdef v{}; if(!d || !gelf_getverdef(d,0,&v)){warn("Invalid version definition."); break;} next=v.vd_next;
                auto*x=chunk(a+v.vd_aux,8,ELF_T_VDEF); GElf_Verdaux aux{}; if(x && gelf_getverdaux(x,0,&aux)) versions[v.vd_ndx&0x7fff]=name(aux.vda_name); else warn("Invalid version definition name.");
            }else{auto*d=chunk(a,16,ELF_T_VNEED); GElf_Verneed v{}; if(!d || !gelf_getverneed(d,0,&v)){warn("Invalid version requirement."); break;} next=v.vn_next; uint64_t b=a+v.vn_aux;
                for(unsigned j=0;j<v.vn_cnt;++j){auto*x=chunk(b,16,ELF_T_VNEED); GElf_Vernaux aux{}; if(!x || !gelf_getvernaux(x,0,&aux)){warn("Invalid required version name."); break;} versions[aux.vna_other&0x7fff]=name(aux.vna_name); if(j+1<v.vn_cnt && aux.vna_next<16){warn("Invalid version chain."); break;} b+=aux.vna_next;}
            }
            if(i+1<total && next<(definitions?20u:16u)){warn("Invalid version chain."); break;} a+=next;
        }
    }; versionsAt(true); versionsAt(false);
    auto* data=elf_getdata_rawchunk(e.get(),symoff,count*entsize,ELF_T_SYM);
    auto* vers=tags.count(DT_VERSYM)?chunk(tags[DT_VERSYM],count*2,ELF_T_HALF):nullptr;
    if(tags.count(DT_VERSYM) && !vers) warn("Invalid symbol version table.");
    size_t budget=256*1024*1024;
    for(uint64_t i=1;data && i<count;++i){GElf_Sym s{}; if(!gelf_getsym(data,i,&s)){warn("Invalid dynamic symbol."); break;} auto bind=GELF_ST_BIND(s.st_info),type=GELF_ST_TYPE(s.st_info),vis=GELF_ST_VISIBILITY(s.st_other);
        if((bind!=STB_GLOBAL && bind!=STB_WEAK && bind!=STB_GNU_UNIQUE) || type==STT_SECTION || type==STT_FILE || (s.st_shndx!=SHN_UNDEF && (vis==STV_HIDDEN || vis==STV_INTERNAL))) continue;
        DynamicSymbol x; x.originalName=name(s.st_name); if(x.originalName.empty()) continue;
        int status=0; std::unique_ptr<char,decltype(&std::free)> dem(abi::__cxa_demangle(x.originalName.c_str(),nullptr,nullptr,&status),&std::free); x.demangledName=status==0 && dem?dem.get():x.originalName;
        if(x.originalName.size()+x.demangledName.size()>budget){warn("Symbol name memory limit reached."); break;} budget-=x.originalName.size()+x.demangledName.size();
        x.imported=s.st_shndx==SHN_UNDEF; x.value=s.st_value; x.size=s.st_size; x.symbolIndex=i;
        x.binding=bind==STB_GLOBAL?"Global":bind==STB_WEAK?"Weak":"GNU unique"; x.visibility=vis==STV_DEFAULT?"Default":vis==STV_PROTECTED?"Protected":vis==STV_HIDDEN?"Hidden":"Internal";
        x.type=type==STT_FUNC?"Function":type==STT_OBJECT?"Object":type==STT_TLS?"TLS":type==STT_GNU_IFUNC?"IFUNC":type==STT_NOTYPE?"No type":"Unknown ("+hex(type)+")";
        if(vers){auto v=static_cast<Elf64_Half*>(vers->d_buf)[i]; unsigned idx=v&0x7fff; if(idx>1){auto it=versions.find(idx); if(it!=versions.end()) x.version=it->second; else warn("Unknown symbol version index."); x.defaultVersion=!x.imported && !(v&0x8000);}}
        r.symbols.push_back(std::move(x));
    }
    if(!data) warn("Cannot decode dynamic symbols.");
    return r;
}
}
