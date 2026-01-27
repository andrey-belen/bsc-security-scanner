/**
 * Migration: Create scans table for storing contract analysis results
 */

exports.up = function(knex) {
  return knex.schema.createTable('scans', function(table) {
    table.increments('id').primary();
    table.string('address', 42).notNullable().index();
    table.timestamp('scan_timestamp').defaultTo(knex.fn.now()).notNullable().index();
    table.text('results_json').notNullable();
    table.string('risk_level', 20).notNullable();
    table.integer('risk_score').notNullable();

    // Composite index for efficient cache lookups
    table.index(['address', 'scan_timestamp'], 'idx_address_timestamp');
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('scans');
};
