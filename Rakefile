# -*- encoding: utf-8 -*-

require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new do |t|
  t.pattern = 'spec/*_spec.rb'
  t.verbose = false
  t.warning = true
end

task :default => 'test'
