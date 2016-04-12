# SecretSharing

# IMPORTANT NEWS

**April 2016 - THIS GEM IS NO LONGER MAINTAINED**

**Good news?** There is a newer better one!

I have created a new `tss` [https://github.com/grempe/tss-rb](https://github.com/grempe/tss-rb)
Ruby Gem (with CLI) that implements Threshold Secret Sharing.

The new version is based on a mature specification, written by a professional
Cryptogropher, and is compatible with at least one other Python implementation
of that spec at the share level. It is **NOT** compatible with this
`secretsharing` gem. There are a number of features of the new code which make
it a better choice not the least of which are:

* MUCH cleaner API, only two entry points (`TSS.split`, `TSS.combine`)
* Split any arbitrary UTF-8 or US-ASCII String
* SHA256 or SHA1 verification of every secret recovered
* Verification hash is split along with the secret, the hash is not known to an attacker
* A binary header with a unique identifier, and the threshold number of shares needed, no more guessing
* More effective sanitization of args, and verification of share formats
* Much cleaner codebase, which closely follows the spec as documented
* Fewer dependencies
* Cryptographically Signed Gem and repository
* Binary and Text share format
* Great test coverage.

You can find the new code at:

[GitHub : https://github.com/grempe/tss-rb](https://github.com/grempe/tss-rb)

[RubyGems : https://rubygems.org/gems/tss](https://rubygems.org/gems/tss)


## Description
A Ruby gem for sharing secrets using [Shamir's Secret Sharing](http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing), which is an [information-theoretic](https://en.wikipedia.org/wiki/Information-theoretic_security) secure method to share secrets between trusted parties.

Shamir's Secret Sharing is an algorithm in cryptography created by Adi Shamir. It is a form of secret sharing, where a secret is divided into parts, giving each participant its own unique part, where some of the parts or all of them are needed in order to reconstruct the secret.

Counting on all participants to combine together the secret might be impractical, and therefore sometimes the threshold scheme is used where any `k` of the total shares `n` are sufficient to reconstruct the original secret.

`k - 1` secret share holders can learn *nothing* about the secret, even when they combine their shares with others. Only once the `k` threshold of shares combined is reached will the original secret be revealed.

## Development History

This library was originally developed by Alexander Klink and later significantly enhanced by Glenn Rempe. You may find the [original source code](http://repo.or.cz/w/secretsharing.git) for Alexander's version still online.

The canonical home for the Gem is now at [grempe/secretsharing](https://github.com/grempe/secretsharing).

WARNING : The major release versions of the Gem may not be API or file compatible with each other.

## Is it safe?

This code has not yet been tested in production by the author. It is well tested though with a full Minitest suite and 100% test code coverage. By all appearances it is working well for what it was designed to do. The code also undergoes a continuous integration test run on many different Ruby runtimes after every push.

The mathematics of the code, which are critical to its operation, and its suitability for use as a security product have not yet been vetted by security minded experts. If you want to help with this please do get in touch.

## Supported platforms

You should be able to use `secretsharing` anywhere that [RbNaCl](https://github.com/cryptosphere/rbnacl) is supported and we do continuous integration testing on the following Rubies:

* MRI 2.0.0, 2.1.4, 2.2.2, HEAD
* JRuby
* JRuby HEAD
* Rubinius

## Installation

Add this to your application's Gemfile:

    gem 'secretsharing'

And then:

    $ bundle

Or install it directly:

    $ gem install secretsharing

Installation also adds a `secretsharing` binary which you can use as a simple CLI for creating and restoring secret shares.

## Example usage in a Ruby program

    require 'secretsharing'

    # create a container (c1) for 3 out of 5 secret sharing
    c1 = SecretSharing::Shamir::Container.new(5,3)

    # create a default secret object with a 32 Byte (256 bit) random secret embedded
    c1.secret = SecretSharing::Shamir::Secret.new

    # or create a fixed secret of your choice by passing in a sufficiently
    # large, cryptographically secure, Integer in the :secret arg
    c1.secret = SecretSharing::Shamir::Secret.new(:secret => 123456789)

    # show the internal secret (a Bignum), as a Base64 encoded String
    puts c1.secret

    # show the Base64 encoded shares generated from that secret
    c1.shares.each { |share| puts share }

    # recover secret from shares by using a new Container (c2)
    # where the number of Shares expected is the same (passing a single
    # argument sets both `n` and `k` to the same value).
    c2 = SecretSharing::Shamir::Container.new(3)

    # the container accepts pushing any SecretSharing::Shamir::Share objects or Strings
    # `c2` will return `false` each time until a valid secret is recovered.
    c2 << c1.shares[0]    #=> false
    c2 << c1.shares[2]    #=> false
    c2 << c1.shares[4]    #=> #<SecretSharing::Shamir::Secret ...>

    # when enough shares are present, the secret will be populated.
    c2.secret? #=> true

    # show the recovered secret (Base64 encoded)
    puts c2.secret

    # test that the newly recovered secret matches the original secret used to create
    # the shares by comparing the embedded HMAC SHA-512 of both.
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

Would you like to create a random 32 Byte secret, or will you provide your own (large Integer)?
1. random
2. fixed
Type? 2
Enter your numeric password:  123456789
How many total shares (n) do you want to distribute?  5
How many of the total shares are required to reveal the secret (k)?  3

========================================
Secret Split Complete

(k) Value: 3
(n) Value: 5

Secret (Bignum):
123456789

Secret (Base64 Compacted & URL Safe):
MjFpM3Y5

Secret has valid_hmac?
true

Shares:
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjEsInkiOjMyMDUzMjE1NCwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjIsInkiOjcyNzM3ODkyNSwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjMsInkiOjU5OTAyOTc2NSwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjQsInkiOjY4MDQ1MjAxMSwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjUsInkiOjIyNjY3ODMyNiwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=

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
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjEsInkiOjMyMDUzMjE1NCwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjIsInkiOjcyNzM3ODkyNSwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=
eyJ2ZXJzaW9uIjoxLCJobWFjIjoiZjNlMjJlNmRhMjcyNzljNDhmZDcxZDBiZmJmNGZlNzk3NGRkYzkxNzRhMDVmYjllMzY2YjQ3YThlZWNmNDcwZiIsImsiOjMsIm4iOjUsIngiOjMsInkiOjU5OTAyOTc2NSwicHJpbWUiOjc0NDk2NzMzNywicHJpbWVfYml0bGVuZ3RoIjoyOX0=


========================================
Secret Recovery Complete

(k) Value: 3

Secret (Fixnum):
123456789

Secret (URL safe Base64 encoded):
MjFpM3Y5

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

    bundle exec ruby -I./lib bin/secretsharing

### Code Quality:

#### Bug Reporting

We love bug reports and pull requests.

<https://github.com/grempe/secretsharing/issues>

#### Travis CI

[![Build Status](https://travis-ci.org/grempe/secretsharing.png)](https://travis-ci.org/grempe/secretsharing)

This gem is tested after each git push to the master branch using the [Travis CI](https://travis-ci.org/grempe/secretsharing) automated build and test service against the supported Ruby runtimes.

A `.travis.yml` file has been added to this project to define which Ruby versions will be tested. Additionally a `gemfiles/Gemfile.ci` file has been created to specify a custom minimal Gemspec to be run on the test hosts.  Contributors should not need to modify these files.

#### Code Climate

[![Code Climate](https://codeclimate.com/github/grempe/secretsharing.png)](https://codeclimate.com/github/grempe/secretsharing)

Code quality and metrics over time are being monitored courtesy of [Code Climate](<https://codeclimate.com>).

<https://codeclimate.com/github/grempe/secretsharing>

#### Rubocop

[RuboCop](https://github.com/bbatsov/rubocop) is a Ruby static code analyzer. Out of the box it will enforce many of the guidelines outlined in the community [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide). A clean `rubocop` run against all `lib` and `spec` code is necessary for a build to be considered for release.

A `.rubocop.yml` file has been added to this project to define any style exceptions.  Contributors should not need to modify this file.

#### COCO

The [COCO](http://lkdjiin.github.io/coco/) gem provides automatic test code coverage analysis for MRI Rubies. It will be run every time `rake test` is run.  If there are any files that are not 100% covered an output report will be generated in `coverage/index.html' and a summary line will be added at the end of the `rake test` output.  It is expected that 100% test coverage will be maintained.

A `.coco.yml` file has been added to this project to define any coverage exceptions.  Contributors should not need to modify this file.

#### Semantic Versioning
This Gems version number tries its best to adhere to
[Semantic Versioning](http://semver.org).

### Contributing

	IMPORTANT
    Please do not change the VERSION number within your commits.
    Please include tests that are passing 100% within your commits.
    Please ensure that you maintain 100% test code coverage as reported by 'coco' which is run after every `rake test` automatically.
    Please run the `rubocop` tool to ensure you are consistent with Ruby style guidelines for this project.

1. Fork the repository
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
