<?php

namespace OhMyBrew\ShopifyApp\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Config;
use OhMyBrew\ShopifyApp\Facades\ShopifyApp;
use OhMyBrew\ShopifyApp\Services\ShopSession;

/**
 * Response for ensuring a proper webhook request.
 */
class AuthWebhook
{
    /**
     * Handle an incoming request to ensure webhook is valid.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $hmac = $request->header('x-shopify-hmac-sha256') ?: '';
        $shop = $request->header('x-shopify-shop-domain');
        $data = $request->getContent();

        $hmacLocal = ShopifyApp::createHmac(['data' => $data, 'raw' => true, 'encode' => true]);
        if (!hash_equals($hmac, $hmacLocal) || empty($shop)) {

            // Issue with HMAC or missing shop header
            return Response::make('Invalid webhook signature.', 401);
        }

        $validation = $this->validateShop($request);
        if ($validation !== true) {
            return Response::make('Invalid shop.', 401);
        }

        // All good, process webhook
        return $next($request);
    }

    /**
     * Checks we have a valid shop.
     *
     * @param \Illuminate\Http\Request $request The request object.
     *
     * @return bool|\Illuminate\Http\RedirectResponse
     */
    protected function validateShop(Request $request)
    {
        // Setup the session service
        $session = new ShopSession();

        $shopDomain = $request->header('x-shopify-shop-domain');

        // Get the shop based on domain and update the session service
        $shopModel = Config::get('shopify-app.shop_model');
        $shop = $shopModel::withTrashed()
            ->where(['shopify_domain' => $shopDomain])
            ->first();
        $session->setShop($shop);

        // We need to do a full flow if no shop or it is deleted
        if ($shop === null || $shop->trashed() || !$session->isValid()) {
            return false;
        }

        // Everything is fine!
        return true;
    }

}
