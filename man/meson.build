if unixy
  man_conf = configuration_data()
  man_desc = fs.read('desc_and_common_options.roff')
  man_conf.set('DESC_AND_COMMON_OPTIONS', man_desc)
  man_example = fs.read('examples_and_security.roff')
  man_conf.set('EXAMPLES_SECURITY', man_example)
  foreach page : ['iodine', 'iodined']
    configure_file(
      input: '@0@.8.in'.format(page),
      output: '@0@.8'.format(page),
      configuration: man_conf,
      install: true,
      install_dir: get_option('mandir') / 'man8',
      install_tag: 'man',
    )
  endforeach
endif
