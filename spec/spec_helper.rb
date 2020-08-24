$LOAD_PATH.unshift File.expand_path("../lib/win32", __dir__)

def windows?
  !!(RUBY_PLATFORM =~ /mswin|mingw|windows/)
end

require "win32-certstore" if windows?

RSpec.configure do |config|
  config.filter_run_excluding windows_only: true unless windows?
end
