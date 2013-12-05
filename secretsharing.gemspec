# -*- encoding: utf-8 -*-

$:.push File.expand_path("../lib", __FILE__)
require "secretsharing/version"

Gem::Specification.new do |s|
  s.name        = "secretsharing"
  s.version     = SecretSharing::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Alexander Klink", "Glenn Rempe"]
  s.email       = ["glenn@rempe.us"]
  s.homepage    = "https://github.com/grempe/secretsharing"
  s.summary     = %q{A Ruby Gem to enable sharing secrets using Shamirs Secret Sharing.}

  s.has_rdoc    = 'true'
  s.extra_rdoc_files = ['README.md']

  s.rubyforge_project = "secretsharing"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {spec}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency 'minitest'
  s.add_development_dependency 'coco'
  s.add_development_dependency 'rb-fsevent'
  s.add_development_dependency 'rerun'
  s.add_development_dependency 'rubocop'
  s.add_development_dependency 'rake'

  s.description =<<'XEOF'
Shamir's Secret Sharing is an algorithm in cryptography. It is a
form of secret sharing, where a secret is divided into parts,
giving each participant its own unique part, where some of the
parts or all of them are needed in order to reconstruct the
secret. Holders of a share gain no knowledge of the larger secret.
XEOF

end
