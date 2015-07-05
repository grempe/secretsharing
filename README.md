# SecretSharing

## Description
A Ruby gem for sharing secrets in an information-theoretically secure way.

It uses Shamir's secret sharing to enable sharing a (random) secret
between n persons where k <= n shares are enough to recover the secret.

k-1 secret share holders learn nothing about the secret when they combine their shares.

Learn More about [Shamir's Secret Sharing](http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing)

## Development History

This library is based on the OpenXPKI::Crypto::Secret::Split Perl module
used in the open source PKI software OpenXPKI, which was written by
Alexander Klink for the OpenXPKI project in 2006.

The original source code for Alexander Klink's 'secretsharing' gem
can be found at <http://repo.or.cz/w/secretsharing.git>

It has been further enhanced, modularized, and a full test suite
has been added by Glenn Rempe (<glenn@rempe.us>) and can be found
at <https://github.com/grempe/secretsharing> which is the new canonical
repository for the gem.

WARNING : The public API and the Share String format of the current version
of the Gem are *not* backwards compatible with 'secretsharing'
versions <= '0.3'.

## Should I use it?

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

    # (or create a fixed secret of your choice by passing in an Integer or OpenSSL::BN in the :secret arg)
    c1.secret = SecretSharing::Shamir::Secret.new(:secret => 123456789)

    # show secret
    puts c1.secret

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

    # Test that the secret used to generate the HMAC
    # matches the HMAC of the secret that was re-constructed
    c2.secret.valid_hmac? #=> true

## Usage via the command line CLI

First, use the `secretsharing` program to generate a set of Shares from a Secret

````
$ secretsharing

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

(k) Value: 3
(n) Value: 5

Secret (Bignum):
179040077567401061920833455639501686558874997550289562553628622313673068089718

Secret (Base64 Compacted & URL Safe):
OXY1eHdod3N0NXJ1MWEzZXBuMjgxZnN1Y2Y4dXI1bWRyNG40dTl2Zmk1MG16OXM4emE=

Secret has valid_hmac?
true

Shares:
2gEqeyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MSwieSI6OTE5NjU5ODE1Njg0MzAwODU5Mjg2OTU1ODMxMzg0NzA2NDQ1NTMyMzQxNDE5ODAyOTA5NzEwMDcxODU1MTgwMjUyMTYxMjk4Nzg0MzE2fQ==

2gEreyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MiwieSI6MjI4MDcyMTc2NjA0NjUwODgwODE1ODY0MTc2ODQyOTY5NDkwODgyODY1OTY4Mzg4MzYyODAyNTE0NTI5MzI4NTE1NDI3Njg3NjM0ODkyNn0=

2gEqeyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MywieSI6NTU2ODc5MDczMDU5OTA2NjU0OTgxNjE5NzQ2NDk2NDU0MDI1MTQzMTkwMjgwNDkxOTQ2NDU4NTExMzAwMjQ4NzY2Nzk5NjUyMzA1NDg5fQ==

2gEreyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6NCwieSI6MzE1ODgyNTQ0NzkxMjczMDkwNjg2NDQzMjgwNjE0MTAwOTg5NzA4NTIxMjIyODIyODg2MTEwODY5NTE2MTQ0NzU5NjE2OTkyMzYxMDEyM30=

2gEreyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6NSwieSI6MjY3NTg2NzE3OTQxNjc0NTA1NjY5ODUzNzkwNjgwNzMzNjQyMjA0NTQ0NjUwODQ5MzM3NTg3NzE3MTU5MTUwNTEzNTk0NzM5MzMwNjcxMH0=

========================================
````

Once that is done you can re-hydrate your Secret using any 3 out of the 5 Shares originally generated:

````
$ secretsharing

Shamir's Secret Sharing

Would you like to 'encode' a new secret as shares, or 'decode' one from existing shares?
1. encode
2. decode
Action? 2

How many of shares (k) are required to reveal this secret?  3

Enter the '3' shares one at a time with a RETURN after each:
2gEqeyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MSwieSI6OTE5NjU5ODE1Njg0MzAwODU5Mjg2OTU1ODMxMzg0NzA2NDQ1NTMyMzQxNDE5ODAyOTA5NzEwMDcxODU1MTgwMjUyMTYxMjk4Nzg0MzE2fQ==
2gEreyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MiwieSI6MjI4MDcyMTc2NjA0NjUwODgwODE1ODY0MTc2ODQyOTY5NDkwODgyODY1OTY4Mzg4MzYyODAyNTE0NTI5MzI4NTE1NDI3Njg3NjM0ODkyNn0=
2gEqeyJobWFjIjoiMDVkNWNlOTIyNjk5ZTUxNzY4ODU2MmJlYjJiZDUzMTI4OTAyYTYzMjAxMjIxMjdjZTVhZjhlMmRiMmY2MmNkMiIsImsiOjMsIm4iOjUsInByaW1lIjozNzA1MzQ2ODU1NTk0MTE4MjUzNTU0MjcxNTIwMjc4MDEzMDUxMzA0NjM5NTA5MzAwNDk4MDQ5MjYyNjQyNjg4MjUzMjIwMTQ4NDc4MDU5LCJwcmltZV9iaXRsZW5ndGgiOjI2MSwidmVyc2lvbiI6MSwieCI6MywieSI6NTU2ODc5MDczMDU5OTA2NjU0OTgxNjE5NzQ2NDk2NDU0MDI1MTQzMTkwMjgwNDkxOTQ2NDU4NTExMzAwMjQ4NzY2Nzk5NjUyMzA1NDg5fQ==


========================================
Decoded Secret:

(k) Value: 3

Secret (Bignum):
179040077567401061920833455639501686558874997550289562553628622313673068089718

Secret (Base64 Compacted & URL Safe):
OXY1eHdod3N0NXJ1MWEzZXBuMjgxZnN1Y2Y4dXI1bWRyNG40dTl2Zmk1MG16OXM4emE=


========================================
````

Easy!

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

    ruby -I./lib bin/secretsharing

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

(c) 2010-2015 Alexander Klink and Glenn Rempe

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

***Alexander Klink***</br>
<secretsharing@alech.de></br>
<http://www.alech.de></br>
@alech on Twitter</br>

***Glenn Rempe***</br>
<glenn@rempe.us></br>
<http://www.rempe.us></br>
@grempe on Twitter</br>
