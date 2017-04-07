require 'rubygems'
require 'bundler'
require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = FileList['spec/**/**/*_spec.rb'].to_a
end

task :default => :spec
