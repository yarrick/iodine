project(
  'iodine',
  'c',
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'warning_level=3',
  ],
  license: 'ISC',
  meson_version: '>=0.64.0',
  version: '0.9.1.99-git' +
    run_command('git', 'rev-parse',  '--short', 'HEAD',
                check: true).stdout().strip(),
)
fs = import('fs')
cc = meson.get_compiler('c')
add_project_arguments(
  cc.get_supported_arguments(['-ffunction-sections','-fdata-sections']),
  language: 'c',
)
add_project_link_arguments(
  cc.get_supported_link_arguments(['-Wl,--gc-sections', '-Wl,-dead_strip']),
  language: 'c',
)

# config.h contents
cdata = configuration_data()
cdata.set_quoted('IODINE_VERSION', meson.project_version())
cdata.set('MAX_USERS', get_option('max_users'))

target_dir = get_option('sbindir')
docdir = get_option('docdir')
if docdir == ''
        docdir = get_option('datadir') / 'doc' / 'iodine'
endif

zlib = dependency('zlib')
commondeps = []
serverdeps = []
package_deps = []

header_args = []
cdata.set10(host_machine.system().to_upper(), true)
if host_machine.system() == 'linux'
  header_args = ['-D_GNU_SOURCE']
  selinux = dependency('libselinux', required: get_option('selinux'))
  cdata.set10('HAVE_SETCON', selinux.found())
  commondeps += selinux
  systemd = dependency('libsystemd', required: get_option('systemd'))
  cdata.set10('HAVE_SYSTEMD', systemd.found())
  serverdeps += systemd
  libcapng = dependency('libcap-ng', required: get_option('libcapng'))
  cdata.set10('HAVE_LIBCAPNG', libcapng.found())
  commondeps += libcapng
  seccomp = dependency('libseccomp', version: '>=2.5.0', required: get_option('seccomp'))
  cdata.set10('HAVE_SECCOMP', seccomp.found())
  commondeps += seccomp
elif host_machine.system() == 'android'
  cdata.set10('LINUX', true)
elif host_machine.system() == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language: 'c')
  add_project_arguments('-DBIND_8_COMPAT', language: 'c')
elif host_machine.system() == 'haiku'
  header_args = ['-D_BSD_SOURCE']
  commondeps += cc.find_library('network')
  commondeps += cc.find_library('bsd')
elif host_machine.system() == 'windows'
  add_project_arguments(
    '-DWINVER=0x0601',
    '-D_WIN32_WINNT=0x0601',
    '-DWIN32_LEAN_AND_MEAN',
    # Avoid TYPE_ALIGNMENT warning from mswsock.h
    cc.get_supported_arguments('-Wno-c23-extensions'),
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
    package_deps += fs.copyfile(
      zlib_dll,
      install: true,
      install_dir: target_dir,
      install_tag: 'runtime',
    )
  endif
endif
add_project_arguments(header_args, language: 'c')

cdata.set10('CAN_DETACH',
            not ['android', 'windows'].contains(host_machine.system()))

optional_functions = [
  'CheckTokenMembership',
  'arc4random_buf',
  'chroot',
  'geteuid',
  'getpwnam',
  'getrandom',
  'pledge',
  'setgroups',
  'strlcpy',
  'syslog',
  'warnx',
]
foreach func : optional_functions
  cdata.set10('HAVE_@0@'.format(func).to_upper(),
    cc.has_function(func, dependencies: commondeps))
endforeach

cdata.set10('HAVE_FD_CLOEXEC', cc.has_header_symbol('fcntl.h', 'FD_CLOEXEC'))
cdata.set10('HAVE_SO_REUSEPORT',
  cc.has_header_symbol('sys/socket.h', 'SO_REUSEPORT', args: header_args))
cdata.set10('HAVE_SO_RTABLE', cc.has_header_symbol('sys/socket.h', 'SO_RTABLE'))
cdata.set10('HAVE_LANDLOCK',
  cc.has_header_symbol('linux/landlock.h', 'LANDLOCK_CREATE_RULESET_VERSION') and
  cc.has_header_symbol('sys/syscall.h', 'SYS_landlock_create_ruleset'))
cdata.set('NORETURN_ATTR',
  cc.has_function_attribute('noreturn') ? '__attribute__((noreturn))' : ''
)
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
  'src/raw.c',
  'src/read.c',
  'src/run_as.c',
  'src/sock.c',
  'src/udp.c',
  'src/ui.c',
  'src/util.c',
)

if host_machine.system() == 'windows'
  common_sources += files('src/tun_windows.c')
  wintun_dll = files('wintun/bin' / host_machine.cpu_family() / 'wintun.dll')
  package_deps += fs.copyfile(
    wintun_dll,
    install: true,
    install_dir: target_dir,
    install_tag: 'runtime',
  )
else
  common_sources += files('src/tun_unix.c')
  cdata.set_quoted('LINUX_TUN_DEV_PATH',
    host_machine.system() == 'android' ? '/dev/tun' : '/dev/net/tun')
  cdata.set_quoted('TUN_NAME_PREFIX',
    host_machine.system() == 'haiku' ? 'tun/' : 'tun')
endif

configure_file(output: 'config.h',
  configuration: cdata)

libcommon = static_library(
  'common',
  common_sources,
  dependencies: commondeps,
)

client_usage = []
server_usage = []
foreach d : [zlib] + commondeps
  if d.type_name() != 'library' and d.found()
    client_usage += '@0@(@1@)'.format(d.name(), d.version())
    server_usage += '@0@(@1@)'.format(d.name(), d.version())
  endif
endforeach
foreach d : serverdeps
  if d.type_name() != 'library' and d.found()
    server_usage += '@0@(@1@)'.format(d.name(), d.version())
  endif
endforeach

iodine = executable('iodine',
  sources: files('src/client.c', 'src/iodine.c'),
  c_args: '-DUSED_LIBS="@0@"'.format(', '.join(client_usage)),
  link_with: libcommon,
  dependencies: zlib,
  install: true,
  install_dir: target_dir,
)

libserver = static_library(
  'server',
  files('src/ext_ip.c', 'src/fw_query.c', 'src/server.c', 'src/user.c'),
  link_with: libcommon,
  dependencies: zlib,
)

iodined = executable('iodined',
  sources: files('src/iodined.c'),
  c_args: '-DUSED_LIBS="@0@"'.format(', '.join(server_usage)),
  link_with: libserver,
  dependencies: serverdeps,
  install: true,
  install_dir: target_dir,
)
package_deps += [iodine, iodined]

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
  install_data(
    'misc/bash-completion/iodine',
    'misc/bash-completion/iodined',
    install_dir: get_option('datadir') / 'bash-completion' / 'completions',
  )
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

py3 = import('python').find_installation()
run_target('package',
  command: [
    py3,
    files('misc/package.py'),
    meson.project_version(),
    host_machine.system(),
    host_machine.cpu_family(),
  ],
  depends: package_deps,
)

subdir('tests')
