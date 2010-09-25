require 'rubygems'

spec = Gem::Specification.new do |gem|
    gem.name        = 'secretsharing'
    gem.version     = '0.2'
    gem.author      = 'Alexander Klink'
    gem.email       = 'secretsharing@alech.de'
    gem.platform    = Gem::Platform::RUBY
    gem.summary     = 'A library to share secrets in an information-theoretically secure way.'
    gem.description =<<'XEOF'
A libary for sharing secrets in an information-theoretically secure way.
It uses Shamir's secret sharing to enable sharing a (random) secret between
n persons where k <= n persons are enough to recover the secret. k-1 secret
share holders learn nothing about the secret when they combine their shares.
XEOF
    gem.test_file   = 'test/test_shamir.rb'
    gem.has_rdoc    = 'true'
    gem.require_path = 'lib'
    gem.extra_rdoc_files = [ 'README' ]

    gem.files = Dir['lib/secretsharing.rb'] + Dir['lib/secretsharing/*'] + Dir['test/test_shamir.rb'] 
end

if $0 == __FILE__
    Gem.manage_gems
    Gem::Builder.new(spec).build
end
