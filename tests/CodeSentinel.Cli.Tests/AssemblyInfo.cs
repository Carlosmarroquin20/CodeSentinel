// Every test in this assembly drives the CLI, which writes to the process-wide
// Console, and several tests swap Console.Out to capture output. Running them in
// parallel let one test write to a writer another test had already disposed
// ("Cannot write to a closed TextWriter"), so they run sequentially.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
