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
cdata.set('IODINE_VERSION', '"@0@"'.format(meson.project_version()))

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
if host_machine.system() == 'android'
  cdata.set10('LINUX', true)
endif
if host_machine.system() == 'gnu'
  add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif
if host_machine.system() == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language: 'c')
endif
if host_machine.system() == 'windows'
  add_project_arguments('-DWINVER=0x0501', language: 'c')
  commondeps += declare_dependency(link_args: ['-lws2_32', '-liphlpapi'])
  cdata.set('sleep(seconds)', 'Sleep((seconds)*1000)')
endif

cc = meson.get_compiler('c')
optional_functions = [
  'arc4random_buf',
  'chroot',
  'daemon',
  'getpwnam',
  'getrandom',
  'inet_aton',
  'setgroups',
  'strlcpy',
  'syslog',
  'warnx',
]
foreach func : optional_functions
  if cc.has_function(func)
    cdata.set10('HAVE_@0@'.format(func).to_upper(), true)
  endif
endforeach

if cc.has_function_attribute('noreturn')
  cdata.set10('HAVE_NORETURN_ATTR', true)
endif

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

py = import('python').find_installation('python3')

base64u_c = custom_target('gen_base64u',
  input : 'src/base64.c',
  output : 'base64u.c',
  command : [
    py, '-c',
    '''
import sys, re;
text = open(sys.argv[1]).read();
text = re.sub(r"([Bb][Aa][Ss][Ee]64)", lambda m: m.group(1) + "u", text);
text = text.replace("0123456789+", "0123456789_");
open(sys.argv[2], "w").write(text)
    ''',
    '@INPUT@', '@OUTPUT@'
  ]
)

common = files([
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
  'src/util.c',
]) + base64u_c

if host_machine.system() == 'windows'
  common += 'src/tun_windows.c'
else
  common += 'src/tun_unix.c'
  if cc.has_header('sys/sockio.h')
    cdata.set10('HAVE_SYS_SOCKIO', true)
  endif
  if cc.has_header_symbol('net/route.h', 'RTM_ADD')
    cdata.set10('HAVE_RTM_ADD', true)
  endif
endif

client = files([
  'src/client.c',
  'src/iodine.c',
])

configure_file(output: 'config.h',
  configuration: cdata)

executable('iodine',
  sources: client + common,
  dependencies: commondeps,
  include_directories: srcdir,
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
  include_directories: srcdir,
  install: true,
  install_dir: get_option('sbindir'))

man_conf = configuration_data()
fs = import('fs')
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

install_data('README.md', install_dir: get_option('datadir') / 'doc' / 'iodine')

libcheck = dependency('check', required: false)

if libcheck.found()
  suites = [
    ['base32', ['src/base32.c']],
    ['base64', ['src/base64.c']],
    ['base64u', [base64u_c]],
    ['common', ['src/common.c', 'src/process.c']],
    ['dns', ['src/base32.c', 'src/dns.c', 'src/encoding.c', 'src/read.c']],
    ['encoding', ['src/encoding.c', 'src/base32.c']],
    ['fw_query', ['src/fw_query.c']],
    ['login', ['src/login.c', 'src/md5.c']],
    ['read', ['src/read.c']],
    ['user', ['src/user.c']],
  ]

  foreach suite : suites
    name = suite[0]
    s = executable('test_@0@'.format(name), [
        'tests/@0@.c'.format(name),
        'tests/test.c',
        'src/compat.c',
      ] + suite[1],
      include_directories: srcdir,
      dependencies: [libcheck, commondeps],
      c_args: '-DSUITE_NAME="@0@"'.format(name))
    test(name, s)
  endforeach
endif
