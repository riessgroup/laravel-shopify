<?php

namespace Osiset\ShopifyApp\Traits;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Redirect;
use Osiset\ShopifyApp\Actions\AuthorizeShop;
use Illuminate\Contracts\View\View as ViewView;
use Osiset\ShopifyApp\Actions\AuthenticateShop;
use Osiset\ShopifyApp\Objects\Values\ShopDomain;

/**
 * Responsible for authenticating the shop.
 */
trait AuthController
{
    /**
     * Index route which displays the login page.
     *
     * @param Request $request The HTTP request.
     *
     * @return ViewView
     */
    public function index(Request $request): ViewView
    {
        return View::make(
            'shopify-app::auth.index',
            ['shopDomain' => $request->query('shop')]
        );
    }

    /**
     * Authenticating a shop.
     *
     * @param AuthenticateShop $authenticateShop The action for authorizing and authenticating a shop.
     *
     * @return ViewView|RedirectResponse
     */
    public function authenticate(Request $request, AuthenticateShop $authenticateShop)
    {
        // Get the shop domain
        $shopDomain = new ShopDomain($request->get('shop'));

        // Run the action, returns [result object, result status]
        list($result, $status) = $authenticateShop($request);

        if ($status === null) {
            // Go to login, something is wrong
            return Redirect::route('install');
        } elseif ($status === false) {
            // No code, redirect to auth URL
            return $this->oauthFailure($result->url, $shopDomain);
        } else {
            // Everything's good... determine if we need to redirect back somewhere
            $return_to = Session::get('return_to');
            if ($return_to) {
                Session::forget('return_to');
                return Redirect::to($return_to);
            }

            // No return_to, go to home route
            return Redirect::route('home');
        }
    }

    /**
     * Simply redirects to Shopify's Oauth screen.
     *
     * @param Request       $request  The request object.
     * @param AuthorizeShop $authShop The action for authenticating a shop.
     *
     * @return ViewView
     */
    public function oauth(Request $request, AuthorizeShop $authShop): ViewView
    {
        // Setup
        $shopDomain = new ShopDomain($request->get('shop'));
        $result = $authShop($shopDomain, null);

        // Redirect
        return $this->oauthFailure($result->url, $shopDomain);
    }

    /**
     * Handles when authentication is unsuccessful or new.
     *
     * @param string     $authUrl    The auth URl to redirect the user to get the code.
     * @param ShopDomain $shopDomain The shop's domain.
     *
     * @return ViewView
     */
    private function oauthFailure(string $authUrl, ShopDomain $shopDomain): ViewView
    {
        return View::make(
            'shopify-app::auth.fullpage_redirect',
            [
                'authUrl'    => $authUrl,
                'shopDomain' => $shopDomain->toNative(),
            ]
        );
    }
}
