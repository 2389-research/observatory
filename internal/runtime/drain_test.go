// ABOUTME: Test-only worker drain leaves lifecycle admission open.
// ABOUTME: Tests must not use shutdown as a wait for successful provisioning.
package runtime

func (m *Manager) WaitForTest() { m.wg.Wait() }
