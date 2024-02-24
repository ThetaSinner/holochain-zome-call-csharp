# Zome call signing with C#

Please note that this code is *VERY* rough, it is just intended to demonstate the steps required to get zome call signing working. It is not a good example of how to write a Holochain client or how to write quality code in general :)

### Setting up

Build the HolochainSerialisationWrapper by running

```
cd HolochainSerialisationWrapper
cargo build --release
cp ./target/release/holochain_serialisation_wrapper.dll ../ZomeCaller/
```

Then you can open VisualStudio using the `ZomeCaller.sln` and read the comments in `Program.cs`. These comments will give you an idea how to tweak the hard-coded values in the `Program.cs` and get Holochain running using the sandbox so that you can run the program.

When you're ready, you shouldn't need to do anything other than hit run on the `ZomeCaller` project using the green run button on your toolbar.

### Expected output

The program dumps quite a bit of debug output. I'm leaving this in place because it was useful to me and I'm hoping it's helpful to see what's going on if anything breaks while extracting this code into a real client.

Please ignore the errors when the program finishes, complaining about websocket state. The websockets do not shut down cleanly, this is expected.

Check for output that says `Capability granted` and `Zome called`. These are the two Holochain interface operations that are being demonstrated so if these lines are printed then the program is working as well as expected!

### Dislaimer about embedded Rust code

I am no expert with FFI. I've done my best to keep memory allocation in C# so that it won't leak memory. Even the hash output memory is allocated in C# and written to by Rust without allocation. However, this is just a best effort by somebody who was learning as they went. Please check and test the code if you intend to copy it!

