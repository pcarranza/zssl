require "optparse"

module Zoocial

    class Options

        attr_reader :mode, :source, :target, :key

        def initialize
            @options = {}
            @parser = OptionParser.new do |opts|
                opts.banner = "usage: zssl [options] MODE SOURCE [TARGET]"
                opts.separator ""
                opts.separator "MODE: e[ncrypt], using a public key or d[ecrypt] using a private key"
                opts.separator ""
                opts.on "-i", "--identity [FILE]", "Key identity file to encrypt or decrypt, DER or PEM encoded, by default it is your ssh key (~/.ssh/id_rsa)" do |v|
                    @options[:key] = v
                end
                opts.separator ""
            end
        end

        def arguments
            return *ARGV
        end

        def parse
            @parser.parse!
        end

        def print_error
            puts "#{$!}"
            puts ""
            puts @parser.help
        end

        def parse!
            begin
                parse
                @mode, @source, @target = arguments
                raise ArgumentError, "Invalid mode '#{@mode}'" if @mode.nil?
                if ['e', 'encrypt'].include? @mode.downcase
                    @mode = :encrypt 
                elsif ['d', 'decrypt'].include? @mode.downcase
                    @mode = :decrypt  
                else
                    raise ArgumentError, "Invalid mode '#{@mode}'"
                end

                open_file = Proc.new do |filename, mode, default|
                    if filename.nil?
                        default
                    else
                        File.open filename, mode
                    end
                end

                unless @options.has_key? :key
                    Dir.glob(File.expand_path('~/.ssh/id_?sa')).each do |f|
                        @options[:key] = f
                    end
                    raise ArgumentError, "No ssh identity found" unless @options.has_key? :key
                end

                @source = open_file.call @source, 'r', $stdin
                @target = open_file.call @target, 'w', $stdout
                @key = open_file.call @options[:key], 'r'
            rescue
                print_error
                exit 1
            end
        end
    end
end
