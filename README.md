== Description
   A library for sharing secrets in an information-theoretically secure way.
   It uses Shamir's secret sharing to enable sharing a (random) secret between
   n persons where k <= n persons are enough to recover the secret. k-1 secret
   share holders learn nothing about the secret when they combine their shares.

   This library is based on the OpenXPKI::Crypto::Secret::Split Perl module used
   in the open source PKI software OpenXPKI, which was written by Alexander Klink
   for the OpenXPKI project in 2006.

   It has been further enhanced for Ruby, and a full minitest test suite added,
   by Glenn Rempe.

== Supported Ruby Versions

   This gem is tested on each push using the Travis CI
   automated build and test tool.  You can view which Ruby
   versions are currently passing or failing (on master branch)
   by visiting:

   https://travis-ci.org/grempe/secretsharing

   Current Travis CI Build Status:

   [![Build Status](https://travis-ci.org/grempe/secretsharing.png)](https://travis-ci.org/grempe/secretsharing)

== Installation Instructions

   gem install secretsharing

   - or -

   # Add the following to your Gemfile
   gem "secretsharing", ">=0.3"

== Usage

   require 'secretsharing'

   # create an object for 3 out of 5 secret sharing
   s = SecretSharing::Shamir.new(5,3)

   # create a random secret (returns the secret)
   s.create_random_secret

   # show secret
   puts s.secret

   # show password representation of secret (Base64)
   puts s.secret_password

   # show shares
   s.shares.each { |share| puts share }

   # recover secret from shares
   s2 = SecretSharing::Shamir.new(3)

   # Accepts SecretSharing::Shamir::Share objects or
   # string representations thereof
   s2 << s.shares[0]
   s2 << s.shares[2]
   s2 << s.shares[4]
   puts s2.secret

== Development and Testing

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

   # View the automated build results on travisci.org
   # for all supported Rubies.
   https://travis-ci.org/grempe/secretsharing

== Copyright
   (c) 2010-2013 Alexander Klink, Glenn Rempe

== License
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

== Warranty
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

== Authors

   Alexander Klink
   secretsharing@alech.de
   http://www.alech.de
   @alech on Twitter

   Glenn Rempe
   glenn@rempe.us
   http://www.rempe.us
   @grempe on Twitter
