package ghidra.file.formats.f2fs;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class F2FSAnalyzer extends FileFormatAnalyzer implements AnalysisWorker {

	@Override
	public String getName() {
		Msg.trace(this, "ENTERED getName");
		return "F2FS Image Annotation (Flash-Friendly File System)";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		Msg.trace(this, "ENTERED getDefaultEnablement");
		return false;
	}

	@Override
	public String getDescription() {
		Msg.trace(this, "ENTERED getDescription");
		return "Annotate F2FS Image files (Flash-Friendly File System)";
	}

	@Override
	public boolean canAnalyze(Program program) {
		Msg.trace(this, "ENTERED canAnalyze");
		try {
			return F2FSUtil.isF2FSImage(program);
		} catch (Exception e) {
			
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		Msg.trace(this, "ENTERED isPrototype");
		return true;
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException {
		Msg.trace(this, "DEBUG analysisWorkerCallback, program: "+program+
				", workerContext: "+workerContext+", monitor: "+monitor);
		return false;
	}

	@Override
	public String getWorkerName() {
		Msg.trace(this, "ENTERED getWorkerName");
		return "F2FSAnalyzer";
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws Exception {
		Msg.trace(this, "DEBUG analysisWorkerCallback, program: "+program+
				", set: "+set+", monitor: "+monitor+", log: "+log);
		return false;
	}

}
