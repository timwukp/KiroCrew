import { afterEach, describe, expect, it, vi } from 'vitest'

const { secureRandomId } = vi.hoisted(() => ({
  secureRandomId: vi.fn(),
}))

vi.mock('../utils/secureId', () => ({ secureRandomId }))

import { mintSendId } from '../pages/chat/ChatPageMessageContent'

describe('ChatPage optimistic send correlation ids', () => {
  afterEach(() => vi.restoreAllMocks())

  it('keeps the compact base36 wire shape while sourcing its nonce securely', () => {
    secureRandomId.mockReturnValue('00000000-0000-4000-8000-000000000000')
    vi.spyOn(Date, 'now').mockReturnValue(36)

    expect(mintSendId()).toBe('s-10-000000')
    expect(secureRandomId).toHaveBeenCalledOnce()
  })
})
