require "simplecov"
require "coveralls"
require "tempfile"

SimpleCov.formatter = Coveralls::SimpleCov::Formatter
SimpleCov.start do
  add_filter "spec"
end

module TestFiles
  def self.create_temporary_random_file
    file = Tempfile.new("random_file")
    file.write(SecureRandom.hex) until file.length > 1024 * 16
    file.close
    TestFiles.ensure_deletion(file)
    file.path
  end

  def self.create_temporary_empty_file(args={:name=>"file", :delete=>true})
    file = Tempfile.new(args[:name])
    file.close
    TestFiles.ensure_deletion(file)
    if args[:delete]
      File.delete(file)
    end
    file.path
  end

  def self.files_are_equal(source, target)
    return false unless File.size(source) == File.size(target)

    p = Proc.new do |one, two|
      one.eachbyte do |byte|
        false unless byte == two.readbyte
      end
      true
    end
  end

  private 
  def self.ensure_deletion(file)
    ObjectSpace.define_finalizer(self, proc { file.delete if File.exist?(file.path) })
  end
end
