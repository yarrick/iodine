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

includes = include_directories('src', 'wintun/include')
target_dir = get_option('sbindir')

zlib = dependency('zlib')
commondeps = [zlib]
serverdeps = []

cdata.set10('@0@'.format(host_machine.system().to_upper()), true)
if host_machine.system() == 'linux'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
  selinux = dependency('libselinux', required: false)
  cdata.set10('HAVE_SETCON', selinux.found())
  commondeps += selinux
  systemd = dependency('libsystemd', required: false)
  if not systemd.found()
    systemd = dependency('libsystemd-daemon', required: false)
  endif
  cdata.set10('HAVE_SYSTEMD', systemd.found())
  serverdeps += systemd
  libcapng = dependency('libcap-ng', required: false)
  cdata.set10('HAVE_LIBCAPNG', libcapng.found())
  commondeps += libcapng
endif
if host_machine.system() == 'android'
  cdata.set10('LINUX', true)
endif
if host_machine.system() == 'gnu'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif
if host_machine.system() == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language: 'c')
  add_project_arguments('-DBIND_8_COMPAT', language: 'c')
endif
if host_machine.system() == 'windows'
  add_project_arguments(
    '-DWINVER=0x0601',
    '-D_WIN32_WINNT=0x0601',
    language: 'c'
  )
  commondeps += cc.find_library('ws2_32', required: true)
  commondeps += cc.find_library('iphlpapi', required: true)
  target_dir = get_option('bindir')
  fs.copyfile(
    'wintun/bin' / host_machine.cpu_family() / 'wintun.dll',
    install:true,
    install_dir: target_dir,
  )

  zdir = zlib.get_variable(pkgconfig: 'exec_prefix', default_value: '')
  if zdir != ''
    zlib_dll = zdir / 'bin' / 'zlib1.dll'
    if fs.exists(zlib_dll)
      fs.copyfile(
        zlib_dll,
        install:true,
        install_dir: target_dir,
      )
    endif
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
  'inet_aton',
  'setgroups',
  'strlcpy',
  'syslog',
  'warnx',
]
foreach func : optional_functions
  cdata.set10('HAVE_@0@'.format(func).to_upper(), cc.has_function(func))
endforeach

cdata.set10('HAVE_FD_CLOEXEC', cc.has_header_symbol('fcntl.h', 'FD_CLOEXEC'))
cdata.set10('HAVE_NORETURN_ATTR', cc.has_function_attribute('noreturn'))

cdata.set10('HAVE_PROGNAME', cc.links('''
  #include <stdio.h>
  extern char *__progname;
  int main() {
    printf("Started as %s\n", __progname);
    return 0;
  }
'''))

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
  'src/read.c',
  'src/run_as.c',
  'src/util.c',
)

if host_machine.system() == 'windows'
  common_sources += files('src/tun_windows.c')
else
  common_sources += files('src/tun_unix.c')
  cdata.set_quoted('LINUX_TUN_DEV_PATH',
    host_machine.system() == 'android' ? '/dev/tun' : '/dev/net/tun')
endif

libcommon = static_library(
  'common',
  common_sources,
  include_directories: includes,
  dependencies: commondeps,
)

configure_file(output: 'config.h',
  configuration: cdata)

client = files(
  'src/client.c',
  'src/iodine.c',
)

executable('iodine',
  sources: client,
  link_with: libcommon,
  include_directories: includes,
  install: true,
  install_dir: target_dir,
)

libserver = static_library(
  'server',
  files('src/fw_query.c', 'src/user.c'),
  include_directories: includes,
)

executable('iodined',
  sources: files('src/iodined.c'),
  link_with: [libcommon, libserver],
  dependencies: serverdeps,
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
    )
  endforeach
endif

install_data('README.md', install_dir: get_option('datadir') / 'doc' / 'iodine')

libcheck = dependency('check', required: false)

if libcheck.found()
  suites = [
    'base32', 'base64', 'base64u', 'base128', 'common', 'dns', 'encoding',
    'fw_query', 'login', 'process', 'read', 'user'
  ]

  # Silence warning from check.h
  # ('warning: token pasting of ',' and __VA_ARGS__ is a GNU extension')
  testargs = []
  if cc.get_id() == 'clang'
    testargs += '-Wno-gnu-zero-variadic-macro-arguments'
  endif

  foreach suite : suites
    test(suite, executable(
      'test_@0@'.format(suite),
      files(
        'tests/@0@.c'.format(suite),
      ),
      link_with: [libcommon, libserver],
      include_directories: includes,
      dependencies: [libcheck],
      c_args: testargs + '-DSUITE_NAME="@0@"'.format(suite),
    ))
  endforeach
endif
