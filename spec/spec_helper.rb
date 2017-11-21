$LOAD_PATH.unshift File.expand_path('../../lib/win32', __FILE__)

def windows?
  !!(RUBY_PLATFORM =~ /mswin|mingw|windows/)
end

RSpec.configure do |config|
  config.filter_run_excluding :windows_only => true unless windows?
end
