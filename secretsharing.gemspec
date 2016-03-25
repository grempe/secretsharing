# -*- encoding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'secretsharing/version'

Gem::Specification.new do |s|
  s.name              = 'secretsharing'
  s.version           = SecretSharing::VERSION
  s.platform          = Gem::Platform::RUBY
  s.authors           = ['Alexander Klink', 'Glenn Rempe']
  s.email             = ['glenn@rempe.us']
  s.homepage          = 'https://github.com/grempe/secretsharing'
  s.summary           = 'A Ruby Gem to enable sharing secrets using Shamirs Secret Sharing.'
  s.license           = 'APACHE 2.0'

  s.has_rdoc          = 'true'
  s.extra_rdoc_files  = ['README.md']

  s.rubyforge_project = 'secretsharing'

  # rubocop:disable Style/SpecialGlobalVars
  s.files             = `git ls-files`.split($/)
  # rubocop:enable Style/SpecialGlobalVars

  s.executables       = s.files.grep(%r{^bin/}) { |f| File.basename(f) }
  s.test_files        = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths     = ['lib']

  s.add_dependency 'rbnacl-libsodium', '~> 1.0.8'
  s.add_dependency 'rbnacl', '~> 3.3.0'
  s.add_dependency 'highline', '~> 1.7.8'
  s.add_dependency 'multi_json', '~> 1.11.2'

  s.add_development_dependency 'mocha'
  s.add_development_dependency 'minitest'
  s.add_development_dependency 'coco'
  s.add_development_dependency 'rb-fsevent'
  s.add_development_dependency 'rerun'
  s.add_development_dependency 'rubocop'
  s.add_development_dependency 'bundler'
  s.add_development_dependency 'rake'

  # http://rubyquicktips.com/post/4438542511/heredoc-and-indent
  s.description = <<-EOF.gsub(/^ {4}/, '')
    Shamirs Secret Sharing is an algorithm in cryptography. It is a
    form of secret sharing, where a secret is divided into parts,
    giving each participant its own unique part, where some of the
    parts or all of them are needed in order to reconstruct the
    secret. Holders of a share gain no knowledge of the larger secret.
    EOF
end
