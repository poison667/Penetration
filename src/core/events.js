import { EventEmitter } from 'node:events';

/**
 * In-process event bus. Domain events (job updates, monitor events, automation
 * triggers, notifications) are published here; the SSE layer subscribes to
 * forward to clients, and the automation engine subscribes to evaluate rules.
 */
class Bus extends EventEmitter {
  constructor() { super(); this.setMaxListeners(200); }
  publish(topic, payload) {
    this.emit('event', { topic, payload, ts: Date.now() });
    this.emit(topic, payload);
  }
}
const globalBus = globalThis.__meridianBus || new Bus();
globalThis.__meridianBus = globalBus;
export const bus = globalBus;
export const TOPICS = {
  jobUpdated: 'job.updated',
  jobCompleted: 'job.completed',
  jobFailed: 'job.failed',
  monitorEvent: 'monitor.event',
  notification: 'notification',
  dataImported: 'data.imported',
  fileChanged: 'file.changed',
  webhook: 'webhook.received',
  findingCreated: 'finding.created',
  reportCreated: 'report.created',
  ticketUpdated: 'ticket.updated',
};
