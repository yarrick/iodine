if unixy
  install_data(
    'bash-completion/iodine',
    'bash-completion/iodined',
    install_dir: get_option('datadir') / 'bash-completion' / 'completions',
  )
endif

run_target('package',
  command: [
    py3,
    files('package.py'),
    meson.project_version(),
    host_machine.system(),
    host_machine.cpu_family(),
  ],
  depends: package_deps,
)
