<script setup lang="ts">
/**
 * DataTable — a semantic table with an optional stacked mobile layout.
 *
 * Props:
 *   - columns: { key, label, align? }[] (required).
 *   - rows: Record<string, unknown>[] (required). Each row must carry a unique
 *     `id` (string|number) used as the render key; a per-row `__key` may be
 *     supplied as a fallback.
 *   - stackOnMobile: under the breakpoint, render each row as a stacked card of
 *     label/value pairs so tables stay readable on small screens.
 *   - caption: optional accessible caption.
 *
 * Slots:
 *   - cell:<key> — custom rendering for a column.
 *   - actions — per-row action buttons; receives the row as slot prop.
 *
 * The <table> always has a real <thead> with <th scope="col"> so it is a proper
 * data table for assistive tech.
 */
export interface TableColumn {
  key: string
  label: string
  align?: 'left' | 'right' | 'center'
}

const props = withDefaults(
  defineProps<{
    columns: TableColumn[]
    rows: Record<string, unknown>[]
    stackOnMobile?: boolean
    caption?: string
    rowKey?: string
  }>(),
  { stackOnMobile: false, caption: '', rowKey: 'id' },
)

function keyFor(row: Record<string, unknown>, index: number): string | number {
  const k = row[props.rowKey]
  if (typeof k === 'string' || typeof k === 'number') return k
  return index
}

function display(value: unknown): string {
  if (value === null || value === undefined) return ''
  return String(value)
}
</script>

<template>
  <div class="data-table" :class="{ 'data-table--stack': props.stackOnMobile }">
    <table class="data-table__table">
      <caption v-if="props.caption" class="visually-hidden">
        {{ props.caption }}
      </caption>
      <thead>
        <tr>
          <th
            v-for="col in props.columns"
            :key="col.key"
            scope="col"
            :class="`data-table__align-${col.align ?? 'left'}`"
          >
            {{ col.label }}
          </th>
          <th v-if="$slots.actions" scope="col" class="data-table__actions-header">
            <span class="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(row, index) in props.rows" :key="keyFor(row, index)">
          <td
            v-for="col in props.columns"
            :key="col.key"
            :data-label="col.label"
            :class="`data-table__align-${col.align ?? 'left'}`"
          >
            <slot :name="`cell:${col.key}`" :row="row" :value="row[col.key]">
              {{ display(row[col.key]) }}
            </slot>
          </td>
          <td v-if="$slots.actions" class="data-table__actions-cell">
            <slot name="actions" :row="row" />
          </td>
        </tr>
      </tbody>
    </table>

    <p v-if="props.rows.length === 0" class="data-table__empty">
      <slot name="empty">No records.</slot>
    </p>
  </div>
</template>

<style scoped>
.data-table__table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--text-sm);
}

.data-table__table th,
.data-table__table td {
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--color-border);
  vertical-align: top;
}

.data-table__table thead th {
  font-weight: var(--weight-semibold);
  color: var(--color-muted);
  background-color: var(--color-surface-alt);
  white-space: nowrap;
}

/* Column alignment via classes — never inline style (strict CSP style-src 'self').
   Every th/td carries an align class (default left), so no rule hard-codes
   text-align where it could out-specify these. */
.data-table__align-left {
  text-align: left;
}

.data-table__align-right {
  text-align: right;
}

.data-table__align-center {
  text-align: center;
}

.data-table__actions-header,
.data-table__actions-cell {
  width: 1%;
  white-space: nowrap;
}

.data-table__empty {
  padding: var(--space-4);
  color: var(--color-muted);
}

/* Stacked mobile layout: turn rows into labelled cards. */
@media (max-width: 640px) {
  .data-table--stack .data-table__table,
  .data-table--stack .data-table__table thead,
  .data-table--stack .data-table__table tbody,
  .data-table--stack .data-table__table tr,
  .data-table--stack .data-table__table td {
    display: block;
    width: 100%;
  }

  .data-table--stack .data-table__table thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
  }

  .data-table--stack .data-table__table tr {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-3);
    background-color: var(--color-surface);
    padding: var(--space-2);
  }

  .data-table--stack .data-table__table td {
    display: flex;
    justify-content: space-between;
    gap: var(--space-4);
    border-bottom: none;
    padding: var(--space-2) var(--space-3);
    text-align: left !important;
  }

  .data-table--stack .data-table__table td::before {
    content: attr(data-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
}
</style>
