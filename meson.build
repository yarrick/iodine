project('iodine', 'c',
  default_options: [
    'c_std=c99',
  ],
  license: 'ISC',
  meson_version: '>=0.60.3',
  version : '0.8.0-git' + run_command('git', 'rev-parse',  '--short', 'HEAD', check: true).stdout().strip(),
)

# config.h contents
cdata = configuration_data()
cdata.set('GITREVISION', '"@0@"'.format(meson.project_version()))

srcdir = include_directories('src')

zlib = dependency('zlib')
commondeps = [zlib]
serverdeps = []

cdata.set10('@0@'.format(host_machine.system().to_upper()), true)
if host_machine.system() == 'linux'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
  selinux = dependency('libselinux', required: false)
  if selinux.found()
    cdata.set10('HAVE_SETCON', true)
    commondeps += selinux
  endif
  systemd = dependency('libsystemd', required: false)
  if not systemd.found()
    systemd = dependency('libsystemd-daemon', required: false)
  endif
  if systemd.found()
    cdata.set10('HAVE_SYSTEMD', true)
    serverdeps += systemd
  endif
endif
if host_machine.system() == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language: 'c')
endif
if host_machine.system() == 'windows'
  add_project_arguments('-DWINVER=0x0501', language: 'c')
  commondeps += declare_dependency(link_args: ['-lws2_32', '-liphlpapi'])
endif

cc = meson.get_compiler('c')
optional_functions = [
  'chroot',
  'daemon',
  'getpwnam',
  'getrandom',
  'setgroups',
]
foreach func : optional_functions
  if cc.has_function(func)
    cdata.set10('HAVE_@0@'.format(func).to_upper(), true)
  endif
endforeach

if cc.links('''
  #include <stdio.h>
  extern char *__progname;
  int main() {
    printf("Started as %s\n", __progname);
    return 0;
  }
''')
  cdata.set10('HAVE_PROGNAME', true)
endif

# For md5
cdata.set10('ARCH_IS_BIG_ENDIAN', host_machine.endian() == 'big')

configure_file(output: 'config.h',
  configuration: cdata)

common = files([
  'src/base32.c',
  'src/base64.c',
  'src/base64u.c',
  'src/base128.c',
  'src/common.c',
  'src/dns.c',
  'src/encoding.c',
  'src/login.c',
  'src/md5.c',
  'src/read.c',
  'src/tun.c',
  'src/util.c',
])

client = files([
  'src/client.c',
  'src/iodine.c',
])

executable('iodine',
  sources: client + common,
  dependencies: commondeps,
  install: true,
  install_dir: get_option('sbindir'))

server = files([
  'src/fw_query.c',
  'src/iodined.c',
  'src/user.c',
])

executable('iodined',
  sources: common + server,
  dependencies: commondeps + serverdeps,
  install: true,
  install_dir: get_option('sbindir'))

install_man('man/iodine.8')
install_data('README.md', install_dir: get_option('datadir') / 'doc' / 'iodine')

libcheck = dependency('check', required: false)

if false and libcheck.found()
  suites = [
    ['base32', []],
    ['base64', []],
    ['common', []],
    ['dns', ['src/base32.c', 'src/encoding.c', 'src/read.c']],
    ['encoding', ['src/base32.c']],
    ['fw_query', []],
    ['login', ['src/md5.c']],
    ['read', []],
    ['user', []],
  ]

  foreach suite : suites
    name = suite[0]
    s = executable('test_@0@'.format(name), [
        'src/@0@.c'.format(name),
        'tests/@0@.c'.format(name),
        'tests/test.c',
      ] + suite[1],
      include_directories: srcdir,
      dependencies: commondeps+libcheck,
      c_args: '-DSUITE_NAME="@0@"'.format(name))
    test(name, s)
  endforeach
endif
