source "https://rubygems.org"

# Specify your gem's dependencies in win32-certstore.gemspec
gemspec

group :docs do
  gem "yard"
  gem "github-markup"
end

group(:development, :test) do
  gem "rake"
  # for testing new chefstyle rules
  gem "chefstyle", git: "https://github.com/chef/chefstyle.git", branch: "master"
end

group :debug do
  gem "pry"
  gem "pry-byebug"
  gem "pry-stack_explorer", "~> 0.6.0" # pin until we drop ruby < 2.6
  gem "rb-readline"
end
