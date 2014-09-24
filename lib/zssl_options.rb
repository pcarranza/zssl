require "optparse"

module Zoocial

  class Options

    attr_reader :mode, :source, :target, :key

    def initialize
      @options = {}
      @parser = OptionParser.new do |opts|
        opts.banner = "usage: zssl [options] MODE [SOURCE] [TARGET]"
        opts.separator ""
        opts.separator "MODE: e[ncrypt], using a public key or d[ecrypt] using a private key"
        opts.separator "SOURCE: a file that exists, if it not declared stdin will be used"
        opts.separator "TARGET: a file that can exist or not, if it not declared stdout will be used"
        opts.separator ""
        opts.on "-i", "--identity [FILE]", "Key identity file to encrypt or decrypt, DER or PEM encoded, by default it is your ssh key (~/.ssh/id_rsa)" do |v|
          @options[:key] = v
        end
        opts.separator ""
      end
    end

    def arguments
      ARGV
    end

    def options
      @options
    end

    def parse
      @parser.parse!
    end

    def print_error e
      puts "#{$!}"
      puts ""
      puts @parser.help
      exit 1
    end

    def parse!
      begin
        parse
        mode, source, target = arguments
        @mode = parse_mode(mode)
        @source = open_file(source, 'r') || $stdin
        @target = open_file(target, 'w') || $stdout
        @key = open_file get_ssh_key, 'r' || raise
      rescue => e
        raise e unless print_error e
      end
    end

    def local_ssh_key
      File.expand_path('~/.ssh/id_rsa')
    end

    private

    def open_file filename, mode
      begin
        return File.open filename, mode unless filename.nil? or filename.empty?
        nil
      rescue Errno::ENOENT
        raise ArgumentError, "File #{filename} could not be found"
      end
    end

    def parse_mode(mode)
      @mode = case mode
              when /^e(ncrypt)?$/i
                :encrypt
              when /^d(ecrypt)?$/i
                :decrypt
              else
                raise ArgumentError, "Mode is mandatory" if mode.nil? or mode.empty?
                raise ArgumentError, "Invalid mode '#{mode}'"
              end
    end

    def get_ssh_key
      key = options.fetch :key, local_ssh_key
      raise ArgumentError, "Could not find valid RSA key" if key.nil? or key.empty?
      key
    end

  end
end
