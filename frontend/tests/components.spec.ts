import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import AlertToast from '@/components/AlertToast.vue'
import Badge from '@/components/Badge.vue'
import Card from '@/components/Card.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import Select from '@/components/Select.vue'
import Button from '@/components/Button.vue'
import TextField from '@/components/TextField.vue'
import Checkbox from '@/components/Checkbox.vue'

describe('Button', () => {
  it('renders the variant class and emits via native click', async () => {
    const wrapper = mount(Button, { props: { variant: 'primary' } })
    expect(wrapper.classes()).toContain('btn--primary')
    await wrapper.trigger('click')
    expect(wrapper.emitted('click')).toBeTruthy()
  })

  it('disables while loading and marks aria-busy', () => {
    const wrapper = mount(Button, { props: { loading: true } })
    expect((wrapper.element as HTMLButtonElement).disabled).toBe(true)
    expect(wrapper.attributes('aria-busy')).toBe('true')
  })
})

describe('TextField', () => {
  it('associates its label and emits update:modelValue', async () => {
    const wrapper = mount(TextField, {
      props: { id: 'key', label: 'Key', modelValue: '' },
    })
    expect(wrapper.get('label').attributes('for')).toBe('key')
    const input = wrapper.get('input')
    await input.setValue('abc')
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual(['abc'])
  })

  it('links an error message via aria-describedby and aria-invalid', () => {
    const wrapper = mount(TextField, {
      props: { id: 'key', label: 'Key', modelValue: '', error: 'Required' },
    })
    const input = wrapper.get('input')
    expect(input.attributes('aria-invalid')).toBe('true')
    const describedBy = input.attributes('aria-describedby')
    expect(wrapper.get(`#${describedBy}`).text()).toBe('Required')
  })
})

describe('Checkbox', () => {
  it('labels itself and emits updates', async () => {
    const wrapper = mount(Checkbox, { props: { id: 'c', label: 'Enable', modelValue: false } })
    expect(wrapper.get('label').attributes('for')).toBe('c')
    await wrapper.get('input').setValue(true)
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([true])
  })
})

describe('ErrorBanner', () => {
  it('is an assertive live region', () => {
    const wrapper = mount(ErrorBanner, { props: { message: 'Boom' } })
    expect(wrapper.attributes('role')).toBe('alert')
    expect(wrapper.attributes('aria-live')).toBe('assertive')
    expect(wrapper.text()).toContain('Boom')
  })
})

describe('AlertToast', () => {
  it('is a polite live region with a dismiss button', async () => {
    const wrapper = mount(AlertToast, { props: { message: 'Saved', duration: 0 } })
    expect(wrapper.attributes('aria-live')).toBe('polite')
    await wrapper.get('.toast__close').trigger('click')
    expect(wrapper.emitted('dismiss')).toBeTruthy()
  })

  it('auto-dismisses after the duration', async () => {
    vi.useFakeTimers()
    const wrapper = mount(AlertToast, { props: { message: 'Saved', duration: 1000 } })
    vi.advanceTimersByTime(1000)
    expect(wrapper.emitted('dismiss')).toBeTruthy()
    vi.useRealTimers()
  })

  it('does not auto-dismiss when duration is 0', async () => {
    vi.useFakeTimers()
    const wrapper = mount(AlertToast, { props: { message: 'Saved', duration: 0 } })
    vi.advanceTimersByTime(10000)
    expect(wrapper.emitted('dismiss')).toBeFalsy()
    vi.useRealTimers()
  })
})

describe('Badge', () => {
  it('defaults to the muted variant and renders slot content', () => {
    const wrapper = mount(Badge, { slots: { default: 'active' } })
    expect(wrapper.classes()).toContain('badge--muted')
    expect(wrapper.text()).toBe('active')
  })

  it('applies the requested variant class', () => {
    const wrapper = mount(Badge, { props: { variant: 'success' } })
    expect(wrapper.classes()).toContain('badge--success')
  })
})

describe('Card', () => {
  it('renders a title heading and body slot', () => {
    const wrapper = mount(Card, {
      props: { title: 'Keys' },
      slots: { default: 'body text' },
    })
    expect(wrapper.get('.card__title').text()).toBe('Keys')
    expect(wrapper.get('.card__body').text()).toBe('body text')
  })

  it('omits the header and footer when neither is provided', () => {
    const wrapper = mount(Card, { slots: { default: 'only body' } })
    expect(wrapper.find('.card__header').exists()).toBe(false)
    expect(wrapper.find('.card__footer').exists()).toBe(false)
  })

  it('renders a footer only when that slot is supplied', () => {
    const wrapper = mount(Card, { slots: { default: 'b', footer: 'actions' } })
    expect(wrapper.get('.card__footer').text()).toBe('actions')
  })
})

describe('EmptyState', () => {
  it('is a status region with the title and message', () => {
    const wrapper = mount(EmptyState, { props: { title: 'No keys', message: 'Create one' } })
    expect(wrapper.attributes('role')).toBe('status')
    expect(wrapper.get('.empty__title').text()).toBe('No keys')
    expect(wrapper.get('.empty__message').text()).toBe('Create one')
  })

  it('renders the actions slot when provided', () => {
    const wrapper = mount(EmptyState, {
      props: { title: 'No keys' },
      slots: { actions: '<button>Add</button>' },
    })
    expect(wrapper.get('.empty__actions').find('button').exists()).toBe(true)
  })
})

describe('LoadingState', () => {
  it('is a polite status region with a default label', () => {
    const wrapper = mount(LoadingState)
    expect(wrapper.attributes('role')).toBe('status')
    expect(wrapper.attributes('aria-live')).toBe('polite')
    expect(wrapper.get('.loading__label').text()).toBe('Loading…')
  })

  it('uses a custom label', () => {
    const wrapper = mount(LoadingState, { props: { label: 'Fetching keys' } })
    expect(wrapper.get('.loading__label').text()).toBe('Fetching keys')
  })
})

describe('PageHeader', () => {
  it('renders the title and description', () => {
    const wrapper = mount(PageHeader, {
      props: { title: 'API Keys', description: 'Manage access' },
    })
    expect(wrapper.get('.page-header__title').text()).toBe('API Keys')
    expect(wrapper.get('.page-header__desc').text()).toBe('Manage access')
  })

  it('renders the actions slot when provided', () => {
    const wrapper = mount(PageHeader, {
      props: { title: 'API Keys' },
      slots: { actions: '<button>New</button>' },
    })
    expect(wrapper.get('.page-header__actions').find('button').exists()).toBe(true)
  })
})

describe('Select', () => {
  const options = [
    { value: 'a', label: 'Alpha' },
    { value: 'b', label: 'Beta' },
  ]

  it('associates its label and renders every option', () => {
    const wrapper = mount(Select, {
      props: { id: 'scope', label: 'Scope', modelValue: 'a', options },
    })
    expect(wrapper.get('label').attributes('for')).toBe('scope')
    expect(wrapper.findAll('option')).toHaveLength(2)
  })

  it('emits update:modelValue on change', async () => {
    const wrapper = mount(Select, {
      props: { id: 'scope', label: 'Scope', modelValue: 'a', options },
    })
    await wrapper.get('select').setValue('b')
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual(['b'])
  })

  it('links an error message via aria-describedby and aria-invalid', () => {
    const wrapper = mount(Select, {
      props: { id: 'scope', label: 'Scope', modelValue: 'a', options, error: 'Pick one' },
    })
    const select = wrapper.get('select')
    expect(select.attributes('aria-invalid')).toBe('true')
    const describedBy = select.attributes('aria-describedby')
    expect(wrapper.get(`#${describedBy}`).text()).toBe('Pick one')
  })
})
