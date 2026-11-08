project('iodine', 'c',
  default_options: [
    'buildtype=release',
    'c_std=c99',
    'warning_level=3',
  ],
  license: 'ISC',
  meson_version: '>=0.64.0',
  version : '0.9.0-git' +
    run_command('git', 'rev-parse',  '--short', 'HEAD',
                check: true).stdout().strip(),
)
fs = import('fs')
cc = meson.get_compiler('c')

# config.h contents
cdata = configuration_data()
cdata.set_quoted('IODINE_VERSION', meson.project_version())

includes = include_directories('.', 'src', 'wintun/include')
target_dir = get_option('sbindir')
docdir = get_option('docdir')
if docdir == ''
        docdir = get_option('datadir') / 'doc' / 'iodine'
endif

zlib = dependency('zlib')
commondeps = []
serverdeps = []

cdata.set10(host_machine.system().to_upper(), true)
if host_machine.system() == 'linux'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
  selinux = dependency('libselinux', required: get_option('selinux'))
  cdata.set10('HAVE_SETCON', selinux.found())
  commondeps += selinux
  systemd = dependency('libsystemd', required: get_option('systemd'))
  cdata.set10('HAVE_SYSTEMD', systemd.found())
  serverdeps += systemd
  libcapng = dependency('libcap-ng', required: get_option('libcapng'))
  cdata.set10('HAVE_LIBCAPNG', libcapng.found())
  commondeps += libcapng
endif
if host_machine.system() == 'android'
  cdata.set10('LINUX', true)
endif
if host_machine.system() == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language: 'c')
  add_project_arguments('-DBIND_8_COMPAT', language: 'c')
endif
if host_machine.system() == 'haiku'
  commondeps += cc.find_library('network')
  commondeps += cc.find_library('bsd')
  add_project_arguments('-D_BSD_SOURCE', language: 'c')
endif
if host_machine.system() == 'windows'
  add_project_arguments(
    '-DWINVER=0x0601',
    '-D_WIN32_WINNT=0x0601',
    language: 'c'
  )
  commondeps += cc.find_library('ws2_32')
  commondeps += cc.find_library('iphlpapi')
  target_dir = get_option('bindir')

  zlib_dll = zlib.get_variable(pkgconfig: 'sharedlibdir',
                               default_value: '') / 'zlib1.dll'
  if not fs.exists(zlib_dll)
    zlib_dll = zlib.get_variable(pkgconfig: 'exec_prefix',
                                 default_value: '') / 'bin' / 'zlib1.dll'
  endif
  if fs.exists(zlib_dll)
    fs.copyfile(
      zlib_dll,
      install: true,
      install_dir: target_dir,
      install_tag: 'runtime',
    )
  endif
endif

cdata.set10('CAN_DETACH',
            not ['android', 'windows'].contains(host_machine.system()))

optional_functions = [
  'CheckTokenMembership',
  'arc4random_buf',
  'chroot',
  'daemon',
  'geteuid',
  'getpwnam',
  'getrandom',
  'setgroups',
  'strlcpy',
  'syslog',
  'tzset',
  'warnx',
]
foreach func : optional_functions
  cdata.set10('HAVE_@0@'.format(func).to_upper(),
    cc.has_function(func, dependencies: commondeps))
endforeach

cdata.set10('HAVE_FD_CLOEXEC', cc.has_header_symbol('fcntl.h', 'FD_CLOEXEC'))
cdata.set10('HAVE_NORETURN_ATTR', cc.has_function_attribute('noreturn'))
cdata.set10('HAVE_FORMAT_ATTR', cc.has_function_attribute('format'))

cdata.set10('HAVE_PROGNAME', cc.links('''
  #include <stdio.h>
  extern char *__progname;
  int main() {
    printf("Started as %s\n", __progname);
    return 0;
  }
'''))

if cc.has_header_symbol('netinet/in.h', 'IP_MTU_DISCOVER')
  cdata.set('IP_OPT_DONT_FRAG', 'IP_MTU_DISCOVER')
  cdata.set('DONT_FRAG_VALUE', 'IP_PMTUDISC_DO')
elif cc.has_header_symbol('netinet/in.h', 'IP_DONTFRAG')
  cdata.set('IP_OPT_DONT_FRAG', 'IP_DONTFRAG')
  cdata.set('DONT_FRAG_VALUE', 1)
elif cc.has_header_symbol('ws2tcpip.h', 'IP_DONTFRAGMENT')
  cdata.set('IP_OPT_DONT_FRAG', 'IP_DONTFRAGMENT')
  cdata.set('DONT_FRAG_VALUE', 1)
endif

if cc.has_header_symbol('netinet/in.h', 'IP_PKTINFO')
  cdata.set('DSTADDR_SOCKOPT', 'IP_PKTINFO')
  cdata.set('SRCADDR_SOCKOPT', 'IP_PKTINFO')
elif cc.has_header_symbol('netinet/in.h', 'IP_RECVDSTADDR')
  cdata.set('DSTADDR_SOCKOPT', 'IP_RECVDSTADDR')
  if cc.has_header_symbol('netinet/in.h', 'IP_SENDSRCADDR')
    cdata.set('SRCADDR_SOCKOPT', 'IP_SENDSRCADDR')
  endif
elif cc.has_header_symbol('ws2tcpip.h', 'IP_PKTINFO')
  cdata.set('DSTADDR_SOCKOPT', 'IP_PKTINFO')
endif

# For md5
cdata.set10('ARCH_IS_BIG_ENDIAN', host_machine.endian() == 'big')

common_sources = files(
  'src/base32.c',
  'src/base64.c',
  'src/base128.c',
  'src/common.c',
  'src/compat.c',
  'src/dns.c',
  'src/encoding.c',
  'src/login.c',
  'src/md5.c',
  'src/process.c',
  'src/random.c',
  'src/read.c',
  'src/run_as.c',
  'src/udp.c',
  'src/ui.c',
  'src/util.c',
)

if host_machine.system() == 'windows'
  common_sources += files('src/tun_windows.c')
  wintun_dll = files('wintun/bin' / host_machine.cpu_family() / 'wintun.dll')
  fs.copyfile(
    wintun_dll,
    install: true,
    install_dir: target_dir,
    install_tag: 'runtime',
  )
else
  common_sources += files('src/tun_unix.c')
  cdata.set_quoted('LINUX_TUN_DEV_PATH',
    host_machine.system() == 'android' ? '/dev/tun' : '/dev/net/tun')
  cdata.set10('TUN_ADD_ROUTE',
    ['netbsd', 'freebsd', 'openbsd', 'darwin'].contains(host_machine.system()))
endif

configure_file(output: 'config.h',
  configuration: cdata)

libcommon = static_library(
  'common',
  common_sources,
  include_directories: includes,
  dependencies: commondeps,
)

executable('iodine',
  sources: files('src/client.c', 'src/iodine.c'),
  link_with: libcommon,
  include_directories: includes,
  dependencies: zlib,
  install: true,
  install_dir: target_dir,
)

libserver = static_library(
  'server',
  files('src/fw_query.c', 'src/user.c'),
  include_directories: includes,
)

executable('iodined',
  sources: files('src/iodined.c', 'src/server.c'),
  link_with: [libcommon, libserver],
  dependencies: serverdeps + zlib,
  include_directories: includes,
  install: true,
  install_dir: target_dir,
)

if not ['android', 'windows'].contains(host_machine.system())
  man_conf = configuration_data()
  man_desc = fs.read('man/desc_and_common_options.roff')
  man_conf.set('DESC_AND_COMMON_OPTIONS', man_desc)
  man_example = fs.read('man/examples_and_security.roff')
  man_conf.set('EXAMPLES_SECURITY', man_example)
  foreach page : ['iodine', 'iodined']
    configure_file(
      input: 'man/@0@.8.in'.format(page),
      output: '@0@.8'.format(page),
      configuration: man_conf,
      install: true,
      install_dir: get_option('mandir') / 'man8',
      install_tag: 'man',
    )
  endforeach
endif

install_data('README.md',
  install_dir: docdir,
  install_tag: 'doc',
)
os_readme = 'README-@0@.txt'.format(host_machine.system())
if fs.exists(os_readme)
  install_data(os_readme,
    install_dir: docdir,
    install_tag: 'doc',
  )
endif

subdir('tests')
