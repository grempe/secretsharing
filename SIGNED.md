##### Signed by https://keybase.io/grempe
```
-----BEGIN PGP SIGNATURE-----

iQIcBAABCgAGBQJUtXiuAAoJEOcWanfPl9CRG6cP/3LrrQItO+olbfYvvp+bFa54
hiK3g6IGYCKAAlocHVCzxNnEczAqCa3/HASkh96RIs0LXznKcFAIjgs/uwZs/Ahh
WYxjI9iPEyJyWffFzDIvA//A2xJCxuzupLc3yqGCTGCsvEf7yVN5fcVe8svzq6ZG
k4BuNzPLONCuzXrtmd7W15F+6M5PD67Rcs+gcHNuZEZOsXnJ3bRsu8GS8LucsxOK
SKsSwLpgJ6vAt3Ef3LSI7SQVMeRRtvgKi2iii/zGwHqRPPoqilpoeLNLlhtTX5Ee
KjfuW9qCU3zEfUs36J0JNtsf1fe0UmdiVvuRtWyM8ONHLJFP4394EwwA/A2QEYil
EYOEd8XkIcIh6lAMAKCNP22gHoJ5ezzlQ/Fk8tMGPlG+C0JVpYzf7+kzlL7iEvG/
y1YC16Cob2whgoLSvt4W7DFADwPm0WRsrdr0QPi0saM60w0fc9+6s8n6YrQEF/rv
vrNbwR7nTT0Hgxqy7F0C6N9l6mS3UOuJvbM2h3QKKI/N7aDZbD4v/SYZjQTD5aXQ
ZVV8KJxykxdHTNlsaUJptO4QFNfnWv0gWc25nDLQ+Io6v3rtV4wYf7JgIRcZgJg9
L6A0B2H1+SXkin7kcxb3ixaIzk0nRTHzF5SKWxGum3Q6wc6WiNE4CcwxuH3Pq2zD
IIhFWwazaio135TTNoj4
=BtEN
-----END PGP SIGNATURE-----

```

<!-- END SIGNATURES -->

### Begin signed statement 

#### Expect

```
size   exec  file                          contents                                                        
             ./                                                                                            
96             .coco.yml                   7c6c72d0ace59753d384d977006da83a0b7bf5333468047529f3e92b4b32b069
168            .gitignore                  cbf96ae3fecba78c775adf62469ecb1161fabf7cd336d166f2b695c02ec105de
296            .rubocop.yml                9e05e042f3c9b14bc52fc7b961cebe26cffdd72f36fea16266ef7622f315e669
182            .travis.yml                 79982d49c16dfef74ac82d239073627e81ab1b4cff7d97721aa1fc047ccc9007
625            CHANGES                     578a7ed1fbc9a0ccdbc148aeae0ce8b3b58cb3f78e23013d8db0aaf98ade49fa
98             Gemfile                     5184edc7cae42cd49ced95779a2035fa6b04edc686450034b7ed731ef2941037
11357          LICENSE.txt                 c81e80664649784c5927f846ba071b04acbb6afaeeea9ee737c8a4a9c8a3bc89
12398          README.md                   7191bb1605c1628dc88ad14d4b846984ed6f4d24148b8c14e49fa74c59085158
205            Rakefile                    52e019b00c55641f894f914df53a40d993ccb90b20731338004269292f4c5d7f
               bin/                                                                                        
3151   x         secretsharing             79efbec8ef0fc6f24417ea490defc6008ac6533ae96dabc0ab7f59c2b385d791
               gemfiles/                                                                                   
101              Gemfile.ci                7e196ea31483bcfd25f626d3ce5eff19ee8c330c44a3ca6b80a4bd8c8aece065
               lib/                                                                                        
                 secretsharing/                                                                            
                   shamir/                                                                                 
3749                 container.rb          37fd7db90e4f2f337db979c93b7022710d443815a0be8f71f3c642902c7cea80
4954                 secret.rb             34ed54e31a4f862ea5f7df2074b7b204dc5400548a47b7f0055fa7050b7ff1e3
6017                 share.rb              a380d5adf64815e62ad4256596b8a05ede61a8c0e7ec1436348946edd3aaed7a
3031               shamir.rb               5702d49cc0e97202e6e0867a0f6955366d407ec4b3fe2d5989bc2259d2776f9f
706                version.rb              428fb8abe60cd3e195e87f1d5f438e03ce797de8ceb699ab18260b7a9a4d9848
863              secretsharing.rb          73deaa58299b597e0540b905f1f713dff526060a9a24c6909cdca83ff23164c4
1733           secretsharing.gemspec       00430997e55126061ec3729438a58ec01e07b07fa846467947f55cfde8285a86
               spec/                                                                                       
12643            shamir_container_spec.rb  39f3e0393cdf50c88fae9ba4302d32dc881fc2ce3b4b8adcd97cf1fb5df026f2
7023             shamir_secret_spec.rb     67533deb4a929155197067106e4149f70bc49b626b08690e8e3611106885ef77
2719             shamir_share_spec.rb      4d2132531310348308c72af976cdc489bb59ef4b77373d5a71dd95b15f3205db
1032             shamir_spec.rb            c5a7e030dad410917a7e52f46f0531a4df8d2f05019e9136a34750f97699b7e2
997              spec_helper.rb            9b634a61716596562288b4c4325e43696af87b48abcd36b34250991aa010caf9
```

#### Ignore

```
/SIGNED.md
```

#### Presets

```
git      # ignore .git and anything as described by .gitignore files
dropbox  # ignore .dropbox-cache and other Dropbox-related files    
kb       # ignore anything as described by .kbignore files          
```

<!-- summarize version = 0.0.9 -->

### End signed statement

<hr>

#### Notes

With keybase you can sign any directory's contents, whether it's a git repo,
source code distribution, or a personal documents folder. It aims to replace the drudgery of:

  1. comparing a zipped file to a detached statement
  2. downloading a public key
  3. confirming it is in fact the author's by reviewing public statements they've made, using it

All in one simple command:

```bash
keybase dir verify
```

There are lots of options, including assertions for automating your checks.

For more info, check out https://keybase.io/docs/command_line/code_signing