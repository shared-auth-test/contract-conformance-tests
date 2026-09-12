import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = '.typespec-json-schema-validator/iam-capability';
const expected = [
  'SharedAuth.Iam.CapabilityCatalog',
  'SharedAuth.Iam.CapabilityCategory',
  'SharedAuth.Iam.CapabilityEvidence',
  'SharedAuth.Iam.CapabilityStatus',
];

const [report, contractIr, verification] = await Promise.all([
  readFile(`${root}/report.json`, 'utf8').then(JSON.parse),
  readFile(`${root}/contract-ir.json`, 'utf8').then(JSON.parse),
  readFile(`${root}/consumer-verification.json`, 'utf8').then(JSON.parse),
]);

assert.equal(report.schema, 'ores.typespec-json-schema-validator.report/v1');
assert.equal(report.status, 'passed');
assert.equal(report.zeroUnexplainedFindings, true);
assert.equal(report.authorities.typespec.authority, 'independently-authored');
assert.equal(
  report.authorities.typespec.generatedJsonSchemaRole,
  'comparison-evidence-only',
);
assert.equal(report.authorities.jsonSchema.authority, 'independently-authored');
assert.equal(
  report.authorities.jsonSchema.dialect,
  'https://json-schema.org/draft/2020-12/schema',
);
assert.equal(report.authorities.precedence, 'none');
assert.equal(report.authorities.onUnexplainedMismatch, 'STOPPED_FOR_EVALUATION');
assert.equal(report.coverage.directDeclarationInventory, true);
assert.equal(report.coverage.typespecGeneratedJsonSchemaComparison, true);
assert.equal(report.coverage.differentialInstanceValidation, true);
assert.equal(report.coverage.sourceMutationCheck, true);
assert.deepEqual(report.coverage.outOfScopeTypeSpecDeclarations, []);
assert.ok(report.differential.summary.corpusInstances >= 10);
assert.equal(report.differential.summary.divergences, 0);
assert.equal(report.differential.summary.refusals, 0);

assert.equal(contractIr.schema, 'ores.typespec-json-schema-validator.contract-ir/v1');
assert.equal(contractIr.status, 'passed');
assert.equal(contractIr.admissible, true);
assert.equal(contractIr.editableAuthority, false);
assert.equal(contractIr.authorities.typespec, 'independently-authored');
assert.equal(contractIr.authorities.jsonSchema, 'independently-authored');
assert.equal(contractIr.authorities.generatedJsonSchema, 'comparison-evidence-only');
assert.equal(contractIr.authorities.precedence, 'none');
assert.deepEqual(
  contractIr.declarations.map(({ id }) => id).sort(),
  expected,
);
assert.deepEqual(contractIr.excludedDeclarations, []);
assert.deepEqual(contractIr.outOfScopeDeclarations, []);

assert.equal(
  verification.schema,
  'ores.typespec-json-schema-validator.consumer-verification-receipt/v1',
);
assert.equal(verification.status, 'passed');
assert.equal(verification.admissible, true);
assert.equal(verification.failureCode, null);
assert.deepEqual([...verification.declarationIds].sort(), expected);
for (const key of ['suppliedIrId', 'computedIrId', 'expectedIrId']) {
  assert.equal(verification[key], contractIr.irId);
}
assert.equal(verification.receiptRunId, report.runId);

const generatedInput = report.inputs.generatedJsonSchema.input;
const authoredInput = report.inputs.authoredJsonSchema.input;
const typespecInput = report.inputs.typespec.input;
assert.notEqual(generatedInput, authoredInput);
assert.notEqual(generatedInput, typespecInput);
assert.notEqual(authoredInput, typespecInput);
assert.match(generatedInput, /\.typespec-json-schema-validator\/iam-capability\/generated/u);
