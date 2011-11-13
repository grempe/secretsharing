require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new do |t|
    t.libs << 'lib'
    t.warning = true
    t.test_files = FileList['test/test_*']
end

task :default => 'test'
