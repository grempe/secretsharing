require 'rake'
require 'rake/testtask'

desc "Install the secretsharing package (non-gem)"
task :install do
    dest = File.join(Config::CONFIG['sitelibdir'], 'secretsharing')
    Dir.mkdir(dest) unless File.exists? dest
    cp 'lib/secretsharing/shamir.rb', dest, :verbose => true
end

desc 'Install the secretsharing package as a gem'
task :install_gem do
    ruby 'secretsharing.gemspec'
    file = Dir["*.gem"].first
    sh "gem install #{file}"
end

Rake::TestTask.new do |t|
    t.libs << 'lib'
    t.warning = true
    t.test_files = FileList['test/test_*']
end
