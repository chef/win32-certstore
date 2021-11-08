source "https://rubygems.org"

# Specify your gem's dependencies in win32-certstore.gemspec
gemspec

gem "mixlib-shellout", "< 3.2.3"
gem "chef-powershell", ">= 1.0.4"

if Gem.ruby_version.to_s.start_with?("2.5")
  # 16.7.23 required ruby 2.6+
  gem "chef-utils", "< 16.7.23" # TODO: remove when we drop ruby 2.5
end

group :docs do
  gem "yard"
  gem "github-markup"
end

group(:development, :test) do
  gem "rake"
  # for testing new chefstyle rules
  gem "chefstyle", git: "https://github.com/chef/chefstyle.git", branch: "main"
end

group :debug do
  gem "pry"
  gem "pry-byebug"
  gem "pry-stack_explorer", "~> 0.4.0" # pin until we drop ruby < 2.6
  gem "rb-readline"
end
