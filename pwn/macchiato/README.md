# Macchiato

Author: `nhwn`

I got tired of people exploiting my poor, defenseless Rust programs, so I wrote this challenge in the ultimate memory-safe language.

## Solution

Looking at the provided source code, an immediate red flag is the usage of `sun.misc.Unsafe` in `BlazinglyFastAccount`. This is an OpenJDK-internal class that allows access to native (and possibly exploitable!) functionality. However, to gain access to the `BlazinglyFastAccount` class, we first need to have a balance equal to `LONG_MAX`. To do this, we can login to a `RegularAccount` and underflow the balance via several withdrawals until it reaches `LONG_MAX`. Now that we have access to `BlazinglyFastAccount`, our goal is to figure out how to escape the bounds check.

```java
private boolean checkBounds(Long index) {
    var geMin = index.compareTo(0L) >= 0;
    var ltMax = index.compareTo(10L) < 0;
    return geMin && ltMax;
}
```

At first glance, it seems impossible to avoid. However, if we look at the code in `Challenge.java`, we see that our input is used to load a static field of an arbitrary static class via [reflection](https://www.oracle.com/technical-resources/articles/java/javareflection.html) (assuming the field has type `Long[]` or `long[]`). 

```java
public static Object load(Class c, String field) {
    try {
        var f = c.getDeclaredField(field);
        f.setAccessible(true);
        return f.get(null);
    } catch (Exception e) {
        return null;
    }
}
```

Since this is OpenJDK 11, we'll get a [warning at runtime for any illegal access](https://openjdk.org/jeps/403), but the access will still be permitted. We can use this to load in the `cache` field of `java.lang.Long$LongCache` as the backing array of a `RegularAccount` (the `$` denotes that `LongCache` is an inner class of `java.lang.Long`).

```java
// https://github.com/openjdk/jdk11/blob/master/src/java.base/share/classes/java/lang/Long.java#L1147-L1156
private static class LongCache {
    private LongCache(){}

    static final Long cache[] = new Long[-(-128) + 127 + 1];

    static {
        for(int i = 0; i < cache.length; i++)
            cache[i] = new Long(i - 128);
    }
}
```

This cache stores pre-allocated objects of type `Long` for the values -128 to 127 (inclusive) and is transparently used during [autoboxing](https://docs.oracle.com/javase/tutorial/java/data/autoboxing.html). Since there is no direct comparison against the upper bound of 10 inside a `RegularAccount`, we can alter the cached `Long` object for 10 (at index 138) and make it `LONG_MAX`, rendering the bounds check in `BlazinglyFastAccount` useless. This gives us arbitrary indexing into the memory beyond the end of `arr` in any `BlazinglyFastAccount`. Given that we can check the current balance and withdraw an arbitrary amount of money, we now have read and write primitives (relative to the address of the `arr` field).

Now, we want to further develop them into arbitrary accesses (i.e., accesses to absolute addresses). To do this, we need to determine the base address of the array at runtime. More concretely, we need to find the current `BlazinglyFastAccount` on the JVM heap since it contains a reference to our array object. Conveniently, we are given the output of `hashCode()` for each accessed account. Contrary to popular belief, this is _not_ the address of the hashed object in OpenJDK 11. Looking at the default parameters within the HotSpot JVM, we see:

```cpp
// https://github.com/openjdk/jdk11/blob/master/src/hotspot/share/runtime/globals.hpp#L856-L857
experimental(intx, hashCode, 5,                                           \
           "(Unstable) select hashCode generation algorithm")           \
```

In the underlying native implementation of `hashCode()`, we have:
```cpp
// https://github.com/openjdk/jdk11/blob/master/src/hotspot/share/runtime/synchronizer.cpp#L669-L708
static inline intptr_t get_next_hash(Thread * Self, oop obj) {
  intptr_t value = 0;
  if (hashCode == 0) {
    // This form uses global Park-Miller RNG.
    // On MP system we'll have lots of RW access to a global, so the
    // mechanism induces lots of coherency traffic.
    value = os::random();
  } else if (hashCode == 1) {
    // This variation has the property of being stable (idempotent)
    // between STW operations.  This can be useful in some of the 1-0
    // synchronization schemes.
    intptr_t addrBits = cast_from_oop<intptr_t>(obj) >> 3;
    value = addrBits ^ (addrBits >> 5) ^ GVars.stwRandom;
  } else if (hashCode == 2) {
    value = 1;            // for sensitivity testing
  } else if (hashCode == 3) {
    value = ++GVars.hcSequence;
  } else if (hashCode == 4) {
    value = cast_from_oop<intptr_t>(obj);
  } else {
    // Marsaglia's xor-shift scheme with thread-specific state
    // This is probably the best overall implementation -- we'll
    // likely make this the default in future releases.
    unsigned t = Self->_hashStateX;
    t ^= (t << 11);
    Self->_hashStateX = Self->_hashStateY;
    Self->_hashStateY = Self->_hashStateZ;
    Self->_hashStateZ = Self->_hashStateW;
    unsigned v = Self->_hashStateW;
    v = (v ^ (v >> 19)) ^ (t ^ (t >> 8));
    Self->_hashStateW = v;
    value = v;
  }

  value &= markOopDesc::hash_mask;
  if (value == 0) value = 0xBAD;
  assert(value != markOopDesc::no_hash, "invariant");
  TEVENT(hashCode: GENERATE);
  return value;
}
```

Thus, the default algorithm generates hashes based on thread-local state. For our purposes, we actually don't care about _how_ the hash is generated; we care about _where_ it's stored. In general, every JVM object has a [header that stores metadata about the object](https://shipilev.net/jvm/objects-inside-out/#_mark_word). In particular, the hash is stored in little-endian within the first few bytes of the mark word. As a result, we can use the leaked hash as a sentinel value to find the beginning of our `BlazinglyFastAccount`. Since the static arrays in `BlazinglyFastBank` are allocated early on in the program, we can be certain that our target `BlazinglyFastAccount` will lie at a higher address within the JVM heap (we have enough memory such that relocation by the garbage collector is not a problem). Thus, we just need to linearly scan past the end of our array until we find an 8-byte chunk that contains our leaked hash (thankfully, objects are aligned to 8 bytes by default in OpenJDK 11, so we're guaranteed that the entire hash will be in a single chunk). Once we find the leaked hash, we then need to retrieve the bytes of the `arr` field. Compressed klass pointers are enabled by default in OpenJDK 11, so we need to look 12 bytes past the beginning of the object header (8 bytes for the mark word and 4 bytes for the klass pointer) to obtain the 4 bytes of our array's address in little-endian (`arr` is the only non-static field in `BlazinglyFastAccount`, so it's immediately after the header). 

Now, we need to interpret our leaked address. While OpenJDK 11 defaults to using [compressed oops](https://www.baeldung.com/jvm-compressed-oops#1basic-optimization) (which right-shifts object addresses by 3 to take advantage of 8-byte alignment), the provided Dockerfile uses `-Xmx64M` in the JVM arguments to constrain the maximum heap space to 64 MB, so object addresses will be absolute and won't require any shifts for adjustment. As a result, we can directly interpret our 4-byte address as the starting address of our array. To compute the base address of the _elements of the array_, we need to add 16 to our address (8 bytes for the mark word, 4 bytes for the klass pointer, and 4 bytes for the array length). By subtracting this computed address from any target address and dividing by 8 (`long` is 8 bytes), we can index into arbitrary 8-byte chunks.

With our new arbitrary read and write primitives, our goal is now arbitrary code execution. Luckily for us, there are several RWX segments present in a JVM process. In particular, OpenJDK 11 maps 0x2000 bytes starting from 0x800000000 as RWX for [class data sharing](https://docs.oracle.com/javase/8/docs/technotes/guides/vm/class-data-sharing.html) (this can be verified from GDB or by causing a segfault and observing the printed memory maps from the resulting JVM crash report). 

```cpp
// https://github.com/openjdk/jdk11/blob/master/src/hotspot/share/memory/metaspaceShared.cpp#L252-L260
// On 64-bit VM, the heap and class space layout will be the same as if
// you're running in -Xshare:on mode:
//
//                              +-- SharedBaseAddress (default = 0x800000000)
//                              v
// +-..---------+---------+ ... +----+----+----+----+----+---------------+
// |    Heap    | Archive |     | MC | RW | RO | MD | OD | class space   |
// +-..---------+---------+ ... +----+----+----+----+----+---------------+
// |<--   MaxHeapSize  -->|     |<-- UnscaledClassSpaceMax = 4GB ------->|
```
```cpp
// https://github.com/openjdk/jdk11/blob/master/src/hotspot/share/memory/metaspaceShared.cpp#L1489-L1491
// AUTHOR'S NOTE: "md" is supposed to be "mc" in the following comment

// NOTE: md contains the trampoline code for method entries, which are patched at run time,
// so it needs to be read/write.
write_region(mapinfo, MetaspaceShared::mc, &_mc_region, /*read_only=*/false,/*allow_exec=*/true);
```

As shown in the above code, this is a _fixed_ address that contains several trampoline entries that jump to loaded methods. Even more conveniently, the region is unpopulated past 0x800001f60 (this can be verified from GDB by examining this address for instructions), so all we need to do is use our arbitrary write primitive to inject shellcode at this address, then patch one of the trampoline entries to jump to our code. Based on rigorous empirical analysis (read: I set several hundred breakpoints in GDB, then checked if any were triggered), the first trampoline entry is used very frequently, so we can use it as our victim entry (this is located at 0x800000000). For our actual shellcode payload, we can just use the standard `shellcraft.sh()` from `pwntools`. The last wrinkle is that our write primitive may need several accesses to set a memory location to a specific value due to the maximum cap of `LONG_MAX` for any given withdrawal, so the patch to the trampoline requires a small change in the amount to be atomic (if a thread jumps to the entry before the write fully goes through, it may either jump to an invalid location or execute an invalid instruction, which will prematurely kill the process). See `solve.py` for the full details.

Flag: `gigem{i_sur3_h0p3_n0b0dy_pwn5_th0s3_3_billi0n_d3v1c3s}`
