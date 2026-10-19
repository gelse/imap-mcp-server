import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import DataTable from '@/components/DataTable.vue'
import { type TableColumn } from '@/components/DataTable.vue'

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'components', 'DataTable.vue'),
  'utf8',
)

const columns: TableColumn[] = [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
]

const rows = [
  { id: 1, name: 'Alice' },
  { id: 2, name: 'Bob' },
]

describe('DataTable', () => {
  it('renders a semantic table with scoped column headers', () => {
    const wrapper = mount(DataTable, { props: { columns, rows } })
    const headers = wrapper.findAll('thead th')
    expect(headers).toHaveLength(2)
    expect(headers[0]!.attributes('scope')).toBe('col')
    expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    expect(wrapper.text()).toContain('Alice')
  })

  it('applies the stack class only when stackOnMobile is set', async () => {
    const wrapper = mount(DataTable, { props: { columns, rows } })
    expect(wrapper.get('.data-table').classes()).not.toContain('data-table--stack')
    await wrapper.setProps({ stackOnMobile: true })
    expect(wrapper.get('.data-table').classes()).toContain('data-table--stack')
  })

  it('carries data-label on cells so the stacked layout can show labels', () => {
    const wrapper = mount(DataTable, { props: { columns, rows, stackOnMobile: true } })
    const firstCell = wrapper.get('tbody td')
    expect(firstCell.attributes('data-label')).toBe('ID')
  })

  it('stacks rows under the mobile breakpoint via CSS media query only', () => {
    // jsdom does not apply media queries; assert the CSS contract: the stacked
    // card layout is scoped to .data-table--stack under a max-width breakpoint.
    const stackMedia = source.match(/@media \(max-width: \d+px\)[\s\S]*?data-table--stack/g)
    expect(stackMedia?.length).toBeGreaterThan(0)
    expect(source).toContain('data-label')
  })

  it('applies align classes to cells instead of inline styles (CSP style-src)', () => {
    const cols: TableColumn[] = [
      { key: 'id', label: 'ID', align: 'right' },
      { key: 'name', label: 'Name' },
    ]
    const wrapper = mount(DataTable, { props: { columns: cols, rows } })
    const headers = wrapper.findAll('thead th')
    expect(headers[0]!.classes()).toContain('data-table__align-right')
    expect(headers[1]!.classes()).toContain('data-table__align-left')
    expect(wrapper.html()).not.toContain('style=')
  })

  it('exposes custom cell slots', () => {
    const wrapper = mount(DataTable, {
      props: { columns, rows },
      slots: {
        'cell:name': `<template #cell:name="{ value }"><strong>{{ value }}</strong></template>`,
      },
      global: { stubs: {} },
    })
    expect(wrapper.html()).toContain('<strong>Alice</strong>')
  })

  it('shows the empty slot when there are no rows', () => {
    const wrapper = mount(DataTable, {
      props: { columns, rows: [] },
      slots: { empty: 'Nothing here' },
    })
    expect(wrapper.text()).toContain('Nothing here')
  })
})
