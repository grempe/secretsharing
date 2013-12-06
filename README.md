# SecretSharing

## Description
A Ruby gem for sharing secrets in an information-theoretically secure way.

It uses Shamir's secret sharing to enable sharing a (random) secret
between n persons where k <= n shares are enough to recover the secret.

k-1 secret share holders learn nothing about the secret when they combine their shares.

Learn More about [Shamir's Secret Sharing](http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing)

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

## Is it ready?

This code has not yet been tested in production.  It is seemingly well tested though with a full Minitest suite and 100% test code coverage and appears to be working well for what it was designed to do.  The code also undergoes a continuous integration test run on many different Ruby runtimes upon every push.

The mathematics of the code, which is critical to its operation, and its suitability for use as a security product have not yet been tested or verified by security minded folks. `Yet`. If you are one of those strongly mathematically or security minded folks please do get in touch if you think you can help validate the current implementation. Suggestions or concerns welcome.

## Installation

Add this line to your application's Gemfile:

    gem 'secretsharing'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install secretsharing

## Usage in a Ruby/Rails project.

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

## Usage via the command line CLI

First, use the `secretsharing` program to generate a set of Shares from a Secret

````
➜  secretsharing git:(master) ✗ secretsharing

Shamir's Secret Sharing

Would you like to 'encode' a new secret as shares, or 'decode' one from existing shares?
1. encode
2. decode
Action? 1

Would you like to create a 'random' secret, or will you provide a 'fixed' one?
1. random
2. fixed
Type? 1
How many total shares (n) do you want to distribute?  5
How many of the total shares (k) are required to reveal the secret?  3

========================================
Encoded Secret:

Base64 URL Safe Secret:
Nm8zajc1MXQ2dmh1aHRranBzdDEzODVjandzMjRqY2RzZGlkMmE1Zjh4ajR4ZXhrMzc=

(k) Value: 3
(n) Value: 5

Secret (Bignum):
121034406494520178855295603459471234790779605059310221238158528187924628493811

Secret (Base64 Compacted & URL Safe):
Nm8zajc1MXQ2dmh1aHRranBzdDEzODVjandzMjRqY2RzZGlkMmE1Zjh4ajR4ZXhrMzc=

Shares:
00183DA68F032EFE2C5CE34D789D01C972DF8A20ADEA42D5FF7C783417DA2D8E36441E6B41
0021623A956EB37FBD251D7F6CE412CD20C45C0D8CB2BF66F77F92E6159D6F68B12FD395541
003ABD9F639A3F84C064D5DE55B5E92E5F35DCA42AD6C0EB05336E6D821EC6906BB3387A41
00460B88B5104598F695DD040EFB36DE6BAFDD82CCEAA248A72B385890B19D9E40D1836B41
00580D654B4D4A3874E4ED67FA1115E231B3C374B1679A885DE08C22858F7BB49257840341

========================================
➜  secretsharing git:(master) ✗
````

Once that is done you can re-hydrate your Secret using any 3 out of the 5 Shares originally generated:

````
➜  secretsharing git:(master) ✗ secretsharing

Shamir's Secret Sharing

Would you like to 'encode' a new secret as shares, or 'decode' one from existing shares?
1. encode
2. decode
Action? 2

How many of shares (k) are required to reveal this secret?  3

Enter the '3' shares one at a time with a RETURN after each:
00183DA68F032EFE2C5CE34D789D01C972DF8A20ADEA42D5FF7C783417DA2D8E36441E6B41
003ABD9F639A3F84C064D5DE55B5E92E5F35DCA42AD6C0EB05336E6D821EC6906BB3387A41
00580D654B4D4A3874E4ED67FA1115E231B3C374B1679A885DE08C22858F7BB49257840341


========================================
Decoded Secret:

(k) Value: 3

Secret (Bignum):
121034406494520178855295603459471234790779605059310221238158528187924628493811

Secret (Base64 Compacted & URL Safe):
Nm8zajc1MXQ2dmh1aHRranBzdDEzODVjandzMjRqY2RzZGlkMmE1Zjh4ajR4ZXhrMzc=

========================================
➜  secretsharing git:(master) ✗
````

Easy!

## Caveats & Warnings

* Due to the nature of how Shamir's Secret Sharing works, it cannot tell you if a cheater has given you a Share that was not part of the original set. So if you have 2 real shares, and 1 cheater share of a valid format, the program will still generate and 'decode' a Secret.  It just won't be the *right* secret!

## Development and Testing

Install the gemfile dependencies:

    bundle install

Run the test suite:

    rake test

Or run the test suite continuously upon watched file changes:

    bundle exec rerun -x rake test

Build and Install the gem to your local system from the cloned repository:

    rake install

Run the `secretsharing` binary without installing the Gem locally:

    ruby -I./lib bin/secretsharing.rb

### Code Quality:

#### Bug Reporting

We love bug reports and pull requests.

<https://github.com/grempe/secretsharing/issues>

#### Travis CI

[![Build Status](https://travis-ci.org/grempe/secretsharing.png)](https://travis-ci.org/grempe/secretsharing)

This gem is tested after each git push to the master branch
using the [Travis CI](https://travis-ci.org/grempe/secretsharing) automated build and test service against several versions of a the most popular Ruby runtimes (MRI 1.8.7, 1.9.3, 2.0.0, JRuby, REE, Rubinious). A build must be green on all of them to be considered for release.

A `.travis.yml` file has been added to this project to define which Ruby versions will be tested. Additionally a `gemfiles/Gemfile.ci` file has been created to specify a custom minimal Gemspec to be run on the test hosts.  Contributors are not to modify these files.

#### Code Climate

[![Code Climate](https://codeclimate.com/github/grempe/secretsharing.png)](https://codeclimate.com/github/grempe/secretsharing)

Code quality and metrics over time are being monitored courtesy of [Code Climate](<https://codeclimate.com>).

<https://codeclimate.com/github/grempe/secretsharing>

#### Rubocop

[RuboCop](https://github.com/bbatsov/rubocop) is a Ruby static code analyzer. Out of the box it will enforce many of the guidelines outlined in the community [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide). A clean `rubocop` run against all `lib` and `spec` code is necessary for a build to be considered for release.

A `.rubocop.yml` file has been added to this project to define any style exceptions.  Contributors are not to modify this file.

#### COCO

The [COCO](http://lkdjiin.github.io/coco/) gem provides automatic test code coverage analysis for ruby 1.9.2, 1.9.3 and 2.0. It will be run every time `rake test` is run.  If there are any files that are not 100% covered an output report will be generated in `coverage/index.html' and a summary line will be added at the end of the `rake test` output.  It is expected that 100% test coverage will be maintained.

A `.coco.yml` file has been added to this project to define any coverage exceptions.  Contributors are not to modify this file.

#### Semantic Versioning
This Gem, and its version number, tries its best to adhere to the
'Semantic Versioning' strategy espoused at : <http://semver.org>

### Contributing

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

## Legal

### Copyright

(c) 2010-2013 Alexander Klink and Glenn Rempe

### License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

### Warranty

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
