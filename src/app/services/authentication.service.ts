import { Injectable } from '@angular/core';
import { AuthConnect, AuthResult, AzureProvider, ProviderOptions, TokenType,OktaProvider } from '@ionic-enterprise/auth';
import { Platform } from '@ionic/angular';
import { nativeIonicAuthOptions, webIonicAuthOptions } from '../../environments/environment';
import { RouteService } from './route.service';
import { VaultService } from './vault.service';
import { checkAuthResult } from './util';
import { PingProvider } from '../types';

@Injectable({ providedIn: 'root' })
export class AuthenticationService {
  private result: AuthResult | undefined;

  constructor(
    private platform: Platform,
    private routeService: RouteService,
    private vaultService: VaultService) {
    this.init();
  }

  /**
   * Initialize: setup Auth Connect, and get token from storage if available
   */
  public async init() {
    await AuthConnect.setup({
      platform: this.platform.is('hybrid') ? 'capacitor' : 'web',
      logLevel: 'NONE',
      ios: {
        webView: 'private',
        safariWebViewOptions: { 
          dismissButtonStyle: 'close', 
          preferredBarTintColor: '#FFFFFF', 
          preferredControlTintColor: '#333333' }
      },
      android: { 
        isAnimated: false, 
        showDefaultShareMenuItem: false },
      web: { 
        uiMode: 'current', 
        authFlow: 'PKCE' }
    });
  }

  /**
   * Login
   */
  public async login() {   
    this.result = await AuthConnect.login(this.pingProvider(), this.getAuthOptions());
    await this.vaultService.set(this.result);
    this.routeService.goToRoot();
  }

  /**
   * Called for the web platform. Passes Auth Connect the auto info from query parameters
   * to get the auth object which we store and redirect to the home page
   */
  public async handleLogin() {
    const urlParams = new URLSearchParams(window.location.search);
    const queryEntries = (Object as any).fromEntries(urlParams.entries());    
    // WN-1241 - providerOptions is optional but if you dont set it the logout method will fail
    this.result = await AuthConnect.handleLoginCallback(queryEntries, this.getAuthOptions());
    await this.vaultService.set(this.result);
    this.routeService.goToRoot();
  }

  /**
   * Logout
   */
  public async logout() {
    //await checkAuthResult(this.result);

    try {
      await AuthConnect.logout(this.pingProvider(), this.result!);
    } catch (error) {
      console.error('AuthConnect.logout', error);
    }
    this.routeService.returnToLogin();
  }

  public async isAuthenticated(): Promise<boolean> {
    try {
      const authResult = await this.vaultService.get();
      if (!authResult) {
        if(this.result) {
          return true
        }
        return false;
      }
      const { idToken } = authResult;
      if (!idToken) {
        throw new Error('No ID Token');
      }

      const expired = await AuthConnect.isAccessTokenExpired(authResult);
      if (!expired) {
        this.result = authResult
        return true;
      }

      const newAuthResult = await AuthConnect.refreshSession(this.pingProvider(), authResult);
      await this.vaultService.set(newAuthResult);
      return true;
    } catch (e) {
      console.error(e);
      await this.vaultService.clear();
      return false;
    }
  }

  public async getAccessToken(): Promise<string | undefined> {
    return await AuthConnect.getToken(TokenType.access, this.result!);
  }

  public decodeToken() {
    return AuthConnect.decodeToken(TokenType.id, this.result!);
  }

  private pingProvider() : PingProvider {
    return new PingProvider();
  }

  private getAuthOptions(): ProviderOptions {
    return this.platform.is('hybrid') ? nativeIonicAuthOptions : webIonicAuthOptions;
  }

}
