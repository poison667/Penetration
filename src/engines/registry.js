import { reconEngine } from './web/recon.js';
import { techDetectEngine } from './web/techdetect.js';
import { headersEngine } from './web/headers.js';
import { crawlEngine } from './web/crawl.js';
import { seoEngine } from './web/seo.js';
import { perfEngine } from './web/perf.js';
import { a11yEngine } from './web/a11y.js';
import { tlsEngine } from './web/tls.js';
import { configEngine } from './sec/config.js';
import { authEngine } from './sec/auth.js';
import { sessionEngine } from './sec/session.js';
import { authzEngine } from './sec/authz.js';
import { validationEngine } from './sec/validation.js';
import { dosEngine } from './sec/dos.js';
import { bizlogicEngine } from './sec/bizlogic.js';
import { cryptoEngine } from './sec/crypto.js';
import { uploadEngine } from './sec/upload.js';
import { paymentEngine } from './sec/payment.js';
import { html5Engine } from './sec/html5.js';

/** Registry of web/security engines (data/document/AI services are handled by dedicated runners). */
export const ENGINES = {
  recon: reconEngine,
  techdetect: techDetectEngine,
  headers: headersEngine,
  crawl: crawlEngine,
  seo: seoEngine,
  perf: perfEngine,
  a11y: a11yEngine,
  sec_transmission: tlsEngine,
  sec_config: configEngine,
  sec_auth: authEngine,
  sec_session: sessionEngine,
  sec_authz: authzEngine,
  sec_validation: validationEngine,
  sec_dos: dosEngine,
  sec_bizlogic: bizlogicEngine,
  sec_crypto: cryptoEngine,
  sec_upload: uploadEngine,
  sec_payment: paymentEngine,
  sec_html5: html5Engine,
};

export function engineKeysForService(service) {
  if (service.engine === 'composite') return service.workflow || [];
  return [service.engine];
}
