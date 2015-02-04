<?php

/**
 * @file
 * Base class for OpenID Connect clients.
 */

abstract class OpenIDConnectClientBase implements OpenIDConnectClientInterface {

  /**
   * The machine name of the client plugin.
   *
   * @var string
   */
  protected $name;

  /**
   * The human-readable name of the client plugin.
   *
   * @var string
   */
  protected $label;

  /**
   * Admin-provided configuration.
   *
   * @var array
   */
  protected $settings;

  public function __construct($name, $label, array $settings) {
    $this->name = $name;
    $this->label = $label;
    $this->settings = $settings;
  }

  public function __toString() {
    return $this->label;
  }

  /**
   * Implements OpenIDConnectClientInterface::getSetting().
   */
  public function getSetting($key, $default = NULL) {
    return isset($this->settings[$key]) ? $this->settings[$key] : $default;
  }

  /**
   * Implements OpenIDConnectClientInterface::settingsForm().
   */
  public function settingsForm() {
    $form['client_id'] = array(
      '#title' => t('Client ID'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('client_id'),
    );
    $form['client_secret'] = array(
      '#title' => t('Client secret'),
      '#type' => 'textarea',
      '#default_value' => $this->getSetting('client_secret'),
    );

    return $form;
  }

  /**
   * Implements OpenIDConnectClientInterface::settingsFormValidate().
   */
  public function settingsFormValidate($form, &$form_state, $error_element_base) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
  }

  /**
   * Implements OpenIDConnectClientInterface::settingsFormSubmit().
   */
  public function settingsFormSubmit($form, &$form_state) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
  }

  /**
   * Implements OpenIDConnectClientInterface::getEndpoints().
   */
  public function getEndpoints() {
    throw new Exception('Unimplemented method getEndpoints().');
  }

  /**
   * Implements OpenIDConnectClientInterface::authorize().
   */
  public function authorize($scope = 'openid email') {
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;

    $query = array(
      'client_id' => $this->getSetting('client_id'),
      'response_type' => 'code',
      'scope' => $scope,
      'redirect_uri' => url($redirect_uri, array('absolute' => TRUE)),
      'state' => openid_connect_create_state_token(),
    );
    
    $endpoints = $this->getEndpoints();
    // Clear $_GET['destination'] because we need to override it.
    unset($_GET['destination']);
    drupal_goto($endpoints['authorization'], $query);
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveIDToken().
   */
  public function retrieveTokens($authorization_code) {
    // Exchange `code` for access token and ID token.
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $post_data = array(
      'code' => $authorization_code,
      'client_id' => $this->getSetting('client_id'),
      'client_secret' => $this->getSetting('client_secret'),
      'redirect_uri' => url($redirect_uri, array('absolute' => TRUE)),
      'grant_type' => 'authorization_code',
    );

    $headers = array('Content-Type' => 'application/x-www-form-urlencoded');
    $data = $this->drupal_http_build_query($post_data);
    $endpoints = $this->getEndpoints();
    $response = drupal_http_request($endpoints['token'], $headers, 'POST',
      $data, 3, 15);

    if (!isset($response->error) && $response->code == 200) {
      $response_data = json_decode($response->data, TRUE);
      return array(
        'id_token' => $response_data['id_token'],
        'access_token' => $response_data['access_token'],
        'expire' => REQUEST_TIME + $response_data['expires_in'],
      );
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * Implements OpenIDConnectClientInterface::decodeIdToken().
   */
  public function decodeIdToken($id_token) {
    list($headerb64, $claims64, $signatureb64) = explode('.', $id_token);
    $claims64 = str_replace(array('-', '_'), array('+', '/'), $claims64);
    $claims64 = base64_decode($claims64);
    return json_decode($claims64, TRUE);
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveUserInfo().
   */
  public function retrieveUserInfo($access_token) {
    $headers = array(
      'Authorization' => 'Bearer ' . $access_token,
    );
    $endpoints = $this->getEndpoints();
    $response = drupal_http_request($endpoints['userinfo'], $headers);
    if (!isset($response->error) && $response->code == 200) {
      return json_decode($response->data, TRUE);
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * Drupal 6 backport of
   * https://api.drupal.org/api/drupal/includes!common.inc/function/drupal_http_build_query/7
   */
  protected function drupal_http_build_query(array $query, $parent = '') {
    $params = array();

    foreach ($query as $key => $value) {
      $key = ($parent ? $parent . '[' . rawurlencode($key) . ']' : rawurlencode($key));

      // Recurse into children.
      if (is_array($value)) {
        $params[] = $this->drupal_http_build_query($value, $key);
      }
      // If a query parameter value is NULL, only append its key.
      elseif (!isset($value)) {
        $params[] = $key;
      }
      else {
        // For better readability of paths in query strings, we decode slashes.
        $params[] = $key . '=' . str_replace('%2F', '/', rawurlencode($value));
      }
    }

    return implode('&', $params);
  }

}
