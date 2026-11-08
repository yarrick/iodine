libcheck = dependency('check', required: false)
if libcheck.found()
  suites = [
    'base32', 'base64', 'base64u', 'base128', 'common', 'compat', 'dns',
    'encoding', 'fw_query', 'login', 'process', 'random', 'read', 'ui', 'user'
  ]

  # Silence warning from check.h
  # ('warning: token pasting of ',' and __VA_ARGS__ is a GNU extension')
  testargs = []
  if cc.get_id() == 'clang'
    testargs += '-Wno-gnu-zero-variadic-macro-arguments'
  endif
  testargs += '-DPROGNAME_SUFFIX=@0@'.format(
    host_machine.system() == 'windows' ? '".exe"' : '""')

  foreach suite : suites
    test(suite, executable(
      'test_@0@'.format(suite),
      files(
        '@0@.c'.format(suite),
      ),
      link_with: [libcommon, libserver],
      include_directories: includes,
      dependencies: [libcheck],
      build_by_default: false,
      c_args: testargs + '-DSUITE_NAME="@0@"'.format(suite),
    ))
  endforeach
endif

tun_ping = executable('tun_ping',
  sources: files('tun_ping.c'),
  build_by_default: false,
  include_directories: includes,
  link_with: libcommon,
)

thin_server = executable('thin_server',
  sources: files('thin_server.c', '../src/server.c'),
  build_by_default: false,
  include_directories: includes,
  dependencies: serverdeps + zlib,
  link_with: [libcommon, libserver],
)

py3 = disabler()
foreach py_name : ['python3', 'python3.14', 'python3.13', 'python3.12']
  if not py3.found()
    py3 = import('python').find_installation(py_name, required: false)
  endif
endforeach
if py3.found()
  bench_deps = [tun_ping]
  if host_machine.system() == 'windows'
    bench_deps += fs.copyfile(wintun_dll)
  endif
  run_target('tun_bench',
    command: [
      py3,
      files('tun_bench.py'),
      tun_ping.full_path(),
      host_machine.system(),
    ],
    depends: bench_deps,
  )
  test_server_deps = [thin_server]
  if host_machine.system() == 'windows' and fs.exists(zlib_dll)
    test_server_deps += fs.copyfile(zlib_dll)
  endif
  run_target('test_server',
    command: [
      py3,
      files('test_server.py'),
      thin_server.full_path(),
      host_machine.system(),
    ],
    depends: test_server_deps,
  )
endif
