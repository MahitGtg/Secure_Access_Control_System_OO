---
title: Oblivionaire Online (OO) project code
---

## Contents

This directory contains a Makefile, C code and configuration files for the "Oblivionaire Online" project.
You should not normally modify the ".h" files in the `src` directory, but _should_ modify the `.c` files
and provide your own implementations of the functions there.

## Building

The Makefile provided will compile object files for all `.c` files
in the `src` directory, and link them together to create an
executable.

The executable will be `bin/app` by default, but you can change this by supplying
a different value for the `TARGET` variable at the command line:

```
$ make TARGET=my-executable all
```

Object files will be created in the `build` directory, which will be created
automatically if it does not already exist.

Any C program requires exactly **one** `main` function. In the provided
code, you will find a `main` function in `src/bogus_main.c`, which
exists only to allow the code to correctly compile and link.

You can **delete** `src/bogus_main.c`, and write other alternative implementations of
`main`. Multiple implementations of `main` can be provided in one file, or in multiple
files, as long as only one is ever compiled and linked at a time.

You can wrap alternative implementations of `main` in `#ifdef` statements to allow you to
select which one to compile.

For instance: one such alternative implementation is in `src/alternate_main`. Delete
`src/bogus_main.c`, and then run

```
$ make CFLAGS='-DALTERNATE_MAIN' clean all
```

(We need `clean` in our Make invocation so that the old `build/bogus_main.o` file gets
deleted. Otherwise both `main` functions would get linked together, and GCC would report
a linkage error. Whenever you swap between `main` implementations, make sure you either
include `clean` in your Make invocation, or delete the old object files manually.)

This will compile and link the `main` implementation in `src/alternate_main.c`
instead of the one in `src/bogus_main.c`.

When we test your code, we will provide our own `main` implementation.

## Installing and configuring libraries

You will almost certainly need to make use of external libraries to complete the project.
There are two files you will need to edit so that the Makefile can find the libraries you
need:

- `apt-packages.txt`: this file should contain a list of Ubuntu packages that are required
  to build your project, and need to be **installed** using `apt-get`. Each line should
  contain the name of one package. You can find the names of packages using `apt-cache search
  <package-substring>`, or by searching online. You can also use `apt-cache show
  <package-name>` to find out more about a particular package.

  Running

  ```
  $ make install-dependencies
  ```

  will install all the packages listed in `apt-packages.txt`. It does not compile or link
  your project.

- `libraries.txt`: this file should contain a list of libraries that GCC needs to **link
  against**. Each line should contain the name of one library. The name of a library is
  typically similar to the name of the Ubuntu package it is contained in, but not always. You
  can find the names of libraries using `pkg-config --list-all`.

  Once you have put a library name in `libraries.txt`, the Makefile will use that to
  automatically work out the correct compiler and linker
  options for the libraries you've specified -- so running `make all` or similar
  should link them correctly.
  (But this won't *install* them; you need to run `make install-dependencies` for that.)


## Testing

A number of testing frameworks are available for C - you are welcome
to use any of them.  We will provide some guidance in the labs on using the `check` framework
(<https://libcheck.github.io/check/>), but you are free to use any other framework you like,
or even create your own.

<!--
  vim: tw=92 :
-->
