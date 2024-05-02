import { AuthConnectConfig, AuthProvider, AuthResult, Manifest, ProviderOptions, ProviderURLInfo, AuthConnect } from "@ionic-enterprise/auth";

export enum SponsorTier {
  Platinum = 'platinum',
  Gold = 'gold',
  Silver = 'silver',
  Bronze = 'bronze'
}
export class HubspotFormData {
  firstname: string;
  lastname: string;
  email: string;
  address: string;
  city: string;
  zip: string;
  country_pl_: string;
  state?: string;
  t_shirt_size: string;
}

export interface AgendaItem {
  id: number;
  title: string;
  description: string;
  speakerIds: number[];
  startTime: string;
  endTime: string;
}

export interface Speaker {
  id: number;
  firstName: string;
  lastName: string;
  companyId: number;
  role: string;
  photoUrl: string;
  biography: string;
  linkedin?: string;
  twitter?: string;
  github?: string;
}

export interface Company {
  id: number;
  name: string;
  logoUrl: string;
}

export type Params = { [key: string]: string };

export enum TokenType {
  id = 'id',
  access = 'access',
  refresh = 'refresh',
}

export interface Sponsor {
  id: number;
  name: string;
  logoUrl: string;
  accentColor: string;
  tier: SponsorTier;
  biography: string;
  homepage: string;
}

export class PingProvider extends AuthProvider {
  async authorizeRequest(
    manifest: Manifest, 
    options: ProviderOptions, 
    config: Pick<AuthConnectConfig,
     "platform" | "ios" | "android" | "web" | "logLevel">): Promise<ProviderURLInfo> {
      await this.checkOrGenerateKeys(config);
      const url = manifest['authorization_endpoint'];

      const params: Params = {};
      params['client_id'] = options.clientId;
      params['redirect_uri'] = options.redirectUri;
      params['scope'] = options.scope;
      params['nonce'] = this.nonce!;
      params['state'] = this.nonce!;
  
      if (this.usePKCE(config)) {
        params['code_challenge_method'] = 'S256';
        params['code_challenge'] = this.key!.challenge;
        params['response_type'] = 'code';
      } else {
        params['response_type'] = 'id_token token';
        params['response_mode'] = 'fragment';
      }
  
      return {
        url,
        params,
      };
  }
  async tokenRequest(manifest: Manifest, options: ProviderOptions, config: Pick<AuthConnectConfig, "platform" | "ios" | "android" | "web" | "logLevel">): Promise<ProviderURLInfo> {
    await this.checkOrGenerateKeys(config);

    const url = manifest['token_endpoint'];

    if (this.usePKCE(config)) {
      const payload: Params = {};
      payload['grant_type'] = 'authorization_code';
      payload['client_id'] = options.clientId;
      payload['code_verifier'] = this.key!.verifier;
      payload['redirect_uri'] = options.redirectUri;
      payload['scope'] = options.scope;

      return {
        url,
        payload,
        tokenCodeName: 'code',
      };
    }

    return { url };
  }
  async refreshTokenRequest(auth?: AuthResult): Promise<ProviderURLInfo> {
    if (!auth) {
      throw new Error('auth result is required');
    }

    const info = await this.tokenRequest(
      auth.provider.manifest,
      auth.provider.options,
      auth.config,
    );

    if (this.usePKCE(auth.config)) {
      if (!info.payload) {
        info.payload = {};
      }
      info.payload['grant_type'] = 'refresh_token';
      info.tokenCodeName = 'refresh_token';
    }

    return info;
  }
  async logoutRequest(auth?: AuthResult): Promise<ProviderURLInfo> {
    if (!auth) {
      throw new Error('auth result is missing');
    }

    const url = auth.provider.manifest['ping_end_session_endpoint'];

    const token = await AuthConnect.getToken(TokenType.id, auth);

    if (!token) {
      throw new Error('could not get id token from auth result');
    }

    const params: Params = {
      TargetResource: auth.provider.options.logoutUrl,
      id_token_hint: token,
    };

    return {
      url,
      params,
    };
  }
  
}