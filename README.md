# SecretSharing

## Description
A Ruby gem for sharing secrets in an information-theoretically secure way.

It uses Shamir's secret sharing to enable sharing a (random) secret
between n persons where k <= n shares are enough to recover the secret.

k-1 secret share holders learn nothing about the secret when they combine their shares.

Learn More:

<http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing>

### Development History

This library is based on the OpenXPKI::Crypto::Secret::Split Perl module
used in the open source PKI software OpenXPKI, which was written by
Alexander Klink for the OpenXPKI project in 2006.

The original source code for Alexander Klink's 'secretsharing' gem
can be found at <http://repo.or.cz/w/secretsharing.git>

It has been further enhanced, modularized, and a full test suite
has been added by Glenn Rempe (<glenn@rempe.us>) and can be found
at <https://github.com/grempe/secretsharing>. The public API of
this new Gem is *not* backwards compatible with 'secretsharing' <= '0.3'.

### Current Travis CI Build Status for all Rubies:

This gem is tested after each git push to the master branch
using the Travis CI automated build and test tool against a large
number of Ruby runtimes (MRI, JRuby, REE, RBX). The current
build status is (click for details):

[![Build Status](https://travis-ci.org/grempe/secretsharing.png)](https://travis-ci.org/grempe/secretsharing)

## Installation

Add this line to your application's Gemfile:

    gem 'secretsharing'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install secretsharing

## Usage

    require 'secretsharing'

    # create an object for 3 out of 5 secret sharing
    c1 = SecretSharing::Shamir::Container.new(5,3)

    # create a random secret (returns the secret)
    c1.secret = SecretSharing::Shamir::Secret.new

    # (or create a fixed secret of your choice by passing in an OpenSSL::BN object)
    c1.secret = SecretSharing::Shamir::Secret.new(OpenSSL::BN.new('123456789'))

    # show secret
    puts c1.secret

    # show password representation of secret (Base64)
    puts c1.secret.to_base64

    # show shares
    c1.shares.each { |share| puts share }

    # recover secret from shares by using a new Container
    # where the number of Shares expected is the same.
    c2 = SecretSharing::Shamir::Container.new(3)

    # Accepts SecretSharing::Shamir::Share objects or
    # string representations thereof
    c2 << c1.shares[0]
    c2 << c1.shares[2]
    c2 << c1.shares[4]

    c2.secret? #=> true
    puts c2.secret

## Development and Testing

    # Install the gemfile dependencies
    bundle install

    # Run the test suite
    rake test

    # Run the test suite continuously
    # upon watched file changes.
    bundle exec rerun -x rake test

    # Install the gem to your local system
    # from the cloned repository code.
    rake install

## Semantic Versioning
This Gem, and its version number, tries its best to adhere to the
'Semantic Versioning 2.0.0' strategy espoused at : <http://semver.org>

## Contributing

	IMPORTANT
    Please do not change the VERSION number within your commits.
    Please include tests that are passing 100% within your commits.
    Please ensure that you maintain 100% test code coverage as reported by 'coco' which is run after every `rake test` automatically.
    Please run the `rubocop` tool to ensure you are consistent with Ruby style guidelines for this project.

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request


## Copyright

(c) 2010-2013 Alexander Klink and Glenn Rempe

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

## Warranty

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the LICENSE.txt file for the
specific language governing permissions and limitations under
the License.

## Authors

***Alexander Klink***  
<secretsharing@alech.de>  
<http://www.alech.de>  
@alech on Twitter  

***Glenn Rempe***  
<glenn@rempe.us>  
<http://www.rempe.us>  
@grempe on Twitter  
