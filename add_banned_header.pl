#!/usr/bin/env perl

# fix up #includes. add banned.h as last header, if not
# already included.

use strict;
use warnings;
use File::Copy qw(copy);
use File::Basename;

sub fix_c_prog {
  my ($infile_path, $outfile_path) = @_;

  open my $in, '<:encoding(UTF-8)', $infile_path
    or die "Cannot open input file '$infile_path': $!";

  my @lines = <$in>;
  close $in;

  my @include_line_idxs;
  my @out_lines;
  my $banned_was_included = 0;

  for my $idx (0 .. $#lines) {
    my $line = $lines[$idx];
    if ($line =~ /^\s*#\s*include\b/) {
      if ($line =~ /["<]banned\.h[">]/) {
        $banned_was_included = 1;
        next;
      }
      push @include_line_idxs, $idx;
    }
    push @out_lines, $line;
  }

  if (@include_line_idxs and not $banned_was_included) {
    my $last_include_index = $include_line_idxs[-1];
    # args are: array, offset, length-to-remove, new_list
    splice @out_lines, $last_include_index + 1, 0, qq[#include "banned.h"\n];
  }

  open my $out, '>:encoding(UTF-8)', $outfile_path
    or die "Cannot open output file '$outfile_path': $!";
  print $out @out_lines;
  close $out;
}

# main
@ARGV == 1 or
  die "Expected 1 arg, file\n";

my $file_to_fix = $ARGV[0];
-f $file_to_fix or die "File does not exist: $file_to_fix";

# Make backup
copy($file_to_fix, "$file_to_fix.BAK")
  or die "Failed to create backup: $!";

eval {
  fix_c_prog($file_to_fix, "$file_to_fix.NEW");
  copy("$file_to_fix.NEW", $file_to_fix)
    or die "Failed to overwrite original file: $!";
};

if ($@) {
  warn "Exception caught: $@\n";
  exit 1;
}


