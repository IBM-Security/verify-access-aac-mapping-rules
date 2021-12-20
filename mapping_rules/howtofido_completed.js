importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// The result of the rule. If false, the mapping rule will be run again. If true,
// the next step in the policy is run, if there is one.
var result = false;

var successFIDO = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "successFIDO");
IDMappingExtUtils.traceString("success from request: " + successFIDO);

macros.put("@FIDO_STATUS@", "ok");

// Set result. Either true for stop running this rule, or false for run the rule
// again.
success.setValue(successFIDO == "success");