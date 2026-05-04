/**
 * Snapshot the `valueIdentityFlow` reachability graph for a tiny
 * program exercising dup / arithmetic / consumer chains. Each
 * row is a (src_line, src_class, sink_line, sink_class) reached
 * via the local-flow identity steps the lib defines.
 *
 * If `LocalFlow::valueIdentityFlowStep` regresses (a pass-through
 * op stops propagating), some of these rows disappear; if it
 * over-approximates (taint creeps through arithmetic), new rows
 * appear. Either is a visible diff.
 */
import codeql.teal.dataflow.Dataflow

from
  Dataflow::Node src,
  Dataflow::Node sink,
  int srcLine,
  int sinkLine,
  string srcStr,
  string sinkStr
where
  LocalFlow::valueIdentityFlow(src, sink) and
  src != sink and
  src.hasLocationInfo(_, srcLine, _, _, _) and
  sink.hasLocationInfo(_, sinkLine, _, _, _) and
  srcStr = src.toString() and
  sinkStr = sink.toString()
select srcLine, srcStr, sinkLine, sinkStr
order by srcLine, sinkLine, srcStr, sinkStr
