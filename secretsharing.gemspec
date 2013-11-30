# -*- encoding: utf-8 -*-

$:.push File.expand_path("../lib", __FILE__)
require "secretsharing/version"

Gem::Specification.new do |s|
  s.name        = "secretsharing"
  s.version     = SecretSharing::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Alexander Klink"]
  s.email       = ["secretsharing@alec.de"]
  s.homepage    = "http://repo.or.cz/w/secretsharing.git"
  s.summary     = %q{A library to share secrets in an information-theoretically secure way.}

  s.description =<<'XEOF'
A libary for sharing secrets in an information-theoretically secure way.
It uses Shamir's secret sharing to enable sharing a (random) secret between
n persons where k <= n persons are enough to recover the secret. k-1 secret
share holders learn nothing about the secret when they combine their shares.
XEOF

  s.has_rdoc    = 'true'
  s.extra_rdoc_files = ['README']

  s.rubyforge_project = "secretsharing"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {spec}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # The libary will make use of Netrand to get
  # random data from Random.org if installed.
  s.add_development_dependency 'netrand'

  s.add_development_dependency 'minitest'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'guard-minitest'
  s.add_development_dependency 'rb-fsevent'
  s.add_development_dependency 'rb-inotify'
  s.add_development_dependency 'rb-fchange'
  s.add_development_dependency 'ruby_gntp' # Growl
  s.add_development_dependency 'rake'
  
end

